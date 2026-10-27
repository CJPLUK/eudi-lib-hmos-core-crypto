package ohos_app_cangjie_entry

import kit.ArkUI.LengthProp
import kit.ArkUI.Column
import kit.ArkUI.Row
import kit.ArkUI.Text
import kit.ArkUI.Button
import kit.ArkUI.CustomView
import kit.ArkUI.CJEntry
import kit.ArkUI.loadNativeView
import kit.ArkUI.FontWeight
import kit.ArkUI.SubscriberManager
import kit.ArkUI.ObservedProperty
import kit.ArkUI.LocalStorage
import ohos.arkui.state_macro_manage.Entry
import ohos.arkui.state_macro_manage.Component
import ohos.arkui.state_macro_manage.State

// Pure-Cangjie test host page. The crypto KAT/behaviour assertions live in the
// sibling *_suite.cj files and run under OpenHarmonyTestRunner (unittest_engine.cj).
@Entry
@Component
class EntryView {
    @State
    var message: String = "EUDI core-crypto Cangjie 测试宿主"

    func build() {
        Row {
            Column {
                Text("EUDI core-crypto (Cangjie HAR)")
                    .fontSize(24)
                    .fontWeight(FontWeight.Bold)
                Text(this.message)
                    .fontSize(14)
            }.width(100.percent)
        }.height(100.percent)
    }
}
