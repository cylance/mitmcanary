from kivy.app import App
from kivy.lang import Builder
from kivy.lib import osc
from kivy.utils import platform
from kivy.clock import Clock
from kivy.core.window import Window
from kivy.properties import ObjectProperty, StringProperty, DictProperty
from kivy.logger import Logger

from kivy.uix.scrollview import ScrollView
from kivy.uix.stacklayout import StackLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.tabbedpanel import TabbedPanel, TabbedPanelHeader, TabbedPanelContent
from kivy.uix.button import Button
from kivy.uix.popup import Popup
from kivy.uix.label import Label

import json

ACTIVITY_PORT = 3001
SERVICE_PORT = 3000
API_OFFSET = "/mitmcanary/"

Builder.load_string('''
<ScrollableLabel>:
    Label:
        size_hint_y: None
        height: self.texture_size[1]
        text_size: self.width, None
        text: root.text
''')


class ScrollableLabel(ScrollView):
    text = StringProperty('')


class ButtonListItem(Button):
    wid = StringProperty('')
    image = StringProperty('')
    title = StringProperty('')
    label = StringProperty('')


class AlertButton(Button):
    alert_id = StringProperty('')
    expected_request_name = StringProperty('')
    timestamp = StringProperty('')
    configuration = StringProperty('')
    raw_message = DictProperty({})

    def on_expected_request_name(self, instance, value):
        self.update_text()

    def on_timestamp(self, instance, value):
        self.update_text()

    def on_configuration(self, instance, value):
        self.update_text()

    def update_text(self):
        self.text = "[{0}] {1} - {2}".format(
            self.timestamp,
            self.expected_request_name,
            self.configuration,
        )

    def build_alert_decision_dialog(self):
        popup = Popup(
            title='Alert Details',
        )

        box = BoxLayout()
        box.orientation = "vertical"

        # todo Fill info box with useful data
        info_box = BoxLayout()
        info_box.orientation = "vertical"
        info_box.size_hint_y = 0.90

        scroll_label = ScrollableLabel(
            text=json.dumps(
                self.raw_message,
                sort_keys=True,
                indent=4,
                separators=(',', ': ')
            )
        )
        info_box.add_widget(scroll_label)

        box.add_widget(info_box)

        button_box = BoxLayout()
        button_box.size_hint_y = 0.10
        button_box.orientation = "horizontal"

        close_button = Button(text="Cancel")
        close_button.bind(on_press=popup.dismiss)
        close_button.size_hint_x = 1
        button_box.add_widget(close_button)

        malicious_button = Button(text="Malicious")
        malicious_button.bind(on_press=lambda x: self.report_malicious(popup))
        button_box.add_widget(malicious_button)

        benign_button = Button(text="Benign")
        benign_button.bind(on_press=lambda x: self.report_benign(popup))
        button_box.add_widget(benign_button)


        box.add_widget(button_box)

        popup.content = box
        return popup

    def report_malicious(self, popup):
        osc.sendMsg(API_OFFSET + "classify-alert", [json.dumps({"id": self.alert_id, "malicious": 1}), ], port=SERVICE_PORT)
        popup.dismiss()
        app.alert_tab_alert_buttons.remove_widget(self)

    def report_benign(self, popup):
        global app
        osc.sendMsg(API_OFFSET + "classify-alert", [json.dumps({"id": self.alert_id, "benign": 1}), ], port=SERVICE_PORT)
        popup.dismiss()
        app.alert_tab_alert_buttons.remove_widget(self)


    def on_release(self):
        popup = self.build_alert_decision_dialog()
        popup.open()



class ButtonList(GridLayout):
    pass


class ServiceApp(App):
    def build(self):
        if platform == 'android':
            from android import AndroidService
            service = AndroidService('my pong service', 'running')
            service.start('service started')
            self.service = service

        osc.init()
        oscid = osc.listen(ipAddr='127.0.0.1', port=ACTIVITY_PORT)
        osc.bind(oscid, self.some_api_callback, API_OFFSET)
        osc.bind(oscid, self.handle_alerts, API_OFFSET + "pending-alerts")
        Clock.schedule_interval(lambda *x: osc.readQueue(oscid), 0)

        Window.size = 640, 480

        self.layout = TabbedPanel()
        self.layout.do_default_tab = True


        #self.status_tab = GridLayout()
        #self.layout.default_tab_content = self.status_tab
        #self.layout.default_tab_text = "Status"
        #self.status_tab.add_widget(Button(text="TODO make this page..."))

        #self.alert_tab = TabbedPanelHeader(text="Alert")
        self.alert_tab_box = BoxLayout()
        self.alert_tab_box.orientation = 'vertical'
        self.alert_tab_box.size_hint = 1, 1
        #self.alert_tab.content = self.alert_tab_box

        self.alert_tab_scroll = ScrollView(
                        size_hint=(1, 1),
                        size=self.alert_tab_box.size,
                        #size=Window.size,
                        scroll_type=['bars', 'content'],
                        do_scroll_y=True,
                        do_scroll_x=False
                    )
        self.alert_tab_box.add_widget(self.alert_tab_scroll)


        self.alert_tab_alert_buttons = ButtonList()
        self.alert_tab_alert_buttons.bind(minimum_height=self.alert_tab_alert_buttons.setter('height'))
        self.alert_tab_alert_buttons.cols = 1
        self.alert_tab_alert_buttons.size_hint_y = None
        self.alert_tab_alert_buttons.row_default_height = '30dp'
        self.alert_tab_alert_buttons.row_force_default = True
        self.alert_tab_alert_buttons.spacing = 0, 0
        self.alert_tab_alert_buttons.padding = 0, 0

        self.alert_tab_scroll.add_widget(self.alert_tab_alert_buttons)


        #self.requests_tab = TabbedPanelHeader(text="Requests")

        self.layout.default_tab_content = self.alert_tab_box
        self.layout.default_tab_text = "Alerts"
        #self.layout.add_widget(self.status_tab)
        #self.layout.add_widget(self.alert_tab)
        #self.layout.add_widget(self.requests_tab)

        self.request_pending_alerts()

        return self.layout

    def request_pending_alerts(self):
        osc.sendMsg(API_OFFSET + "pending-alerts", ['', ], port=SERVICE_PORT)

    def handle_alerts(self, message, *args):
        alerts = json.loads(message[2])
        for i, a in alerts["alerts"].items():
            self.add_alert_button(
                a["expected_request_name"],
                a["timestamp"],
                i,
                a["expected_request_configuration"],
                a
            )

    def configuration_to_string(self, config):
        return ", ".join(["{0} = {1}".format(k, v) for k, v in config.items()])

    def remove_alert_button(self, alert_id):
        # todo DO THIS
        pass

    def add_alert_button(self,
                         expected_request_name,
                         timestamp,
                         alert_id,
                         expected_request_config,
                         raw_message
                         ):
        # todo Search for duplicates
        ab = AlertButton()
        ab.expected_request_name = expected_request_name
        ab.timestamp = timestamp
        ab.alert_id = alert_id
        ab.configuration = self.configuration_to_string(expected_request_config)
        ab.raw_message = raw_message
        self.alert_tab_alert_buttons.add_widget(ab)

    def some_api_callback(self, message, *args):
        print "THIS FUNCTION DOES NOTHING!", message
        #self.add_alert_button("butt request", "10", "1")

    def ping(self):
        print "Sending ping..."
        osc.sendMsg(API_OFFSET, ['ping', ], port=SERVICE_PORT)

if __name__ == '__main__':
    app = ServiceApp()
    app.run()
