#include "JsInjector.h"

#include <QWebEngineScriptCollection>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QComboBox>
#include <QCheckBox>
#include <QPushButton>
#include <QLabel>
#include <QDialogButtonBox>
#include <QListWidget>
#include <QSplitter>
#include <QMessageBox>
#include <QFont>

namespace Fidra {

ScriptEditorDialog::ScriptEditorDialog(QWidget* Parent)
    : QDialog(Parent)
    , NameEdit(nullptr)
    , CodeEdit(nullptr)
    , InjectionPointCombo(nullptr)
    , EnabledCheck(nullptr) {
    SetupUi();
}

ScriptEditorDialog::~ScriptEditorDialog() {
}

void ScriptEditorDialog::SetupUi() {
    setWindowTitle(QStringLiteral("Script Editor"));
    setMinimumSize(600, 400);

    QVBoxLayout* Layout = new QVBoxLayout(this);

    QHBoxLayout* NameLayout = new QHBoxLayout();
    QLabel* NameLabel = new QLabel(QStringLiteral("Name:"), this);
    NameEdit = new QLineEdit(this);
    NameLayout->addWidget(NameLabel);
    NameLayout->addWidget(NameEdit);
    Layout->addLayout(NameLayout);

    QHBoxLayout* OptionsLayout = new QHBoxLayout();

    QLabel* InjectionLabel = new QLabel(QStringLiteral("Injection Point:"), this);
    InjectionPointCombo = new QComboBox(this);
    InjectionPointCombo->addItem(QStringLiteral("Document Creation"), QWebEngineScript::DocumentCreation);
    InjectionPointCombo->addItem(QStringLiteral("Document Ready"), QWebEngineScript::DocumentReady);
    InjectionPointCombo->addItem(QStringLiteral("Deferred"), QWebEngineScript::Deferred);

    EnabledCheck = new QCheckBox(QStringLiteral("Enabled"), this);
    EnabledCheck->setChecked(true);

    OptionsLayout->addWidget(InjectionLabel);
    OptionsLayout->addWidget(InjectionPointCombo);
    OptionsLayout->addStretch();
    OptionsLayout->addWidget(EnabledCheck);
    Layout->addLayout(OptionsLayout);

    CodeEdit = new QPlainTextEdit(this);
    CodeEdit->setFont(QFont(QStringLiteral("Consolas"), 10));
    CodeEdit->setTabStopDistance(28);
    Layout->addWidget(CodeEdit, 1);

    QDialogButtonBox* ButtonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    connect(ButtonBox, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(ButtonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);
    Layout->addWidget(ButtonBox);
}

void ScriptEditorDialog::SetScript(const UserScript& Script) {
    NameEdit->setText(Script.Name);
    CodeEdit->setPlainText(Script.Code);
    EnabledCheck->setChecked(Script.Enabled);

    for (int I = 0; I < InjectionPointCombo->count(); I++) {
        if (InjectionPointCombo->itemData(I).toInt() == Script.InjectionPoint) {
            InjectionPointCombo->setCurrentIndex(I);
            break;
        }
    }
}

UserScript ScriptEditorDialog::GetScript() const {
    UserScript Script;
    Script.Name = NameEdit->text();
    Script.Code = CodeEdit->toPlainText();
    Script.Enabled = EnabledCheck->isChecked();
    Script.InjectionPoint = static_cast<QWebEngineScript::InjectionPoint>(
        InjectionPointCombo->currentData().toInt());
    Script.WorldId = 0;
    return Script;
}

JsInjector::JsInjector(QWebEngineProfile* Profile, QObject* Parent)
    : QObject(Parent)
    , TargetProfile(Profile) {
}

JsInjector::~JsInjector() {
}

void JsInjector::InjectScript(const QWebEngineScript& Script) {
    TargetProfile->scripts()->insert(Script);
}

void JsInjector::RemoveScript(const QString& Name) {
    auto ExistingList = TargetProfile->scripts()->find(Name);
    for (const auto& Existing : ExistingList) {
        TargetProfile->scripts()->remove(Existing);
    }
}

void JsInjector::ClearAllScripts() {
    TargetProfile->scripts()->clear();
}

void JsInjector::InjectConsoleHook() {
    QString Source;
    Source += QStringLiteral("(function() {\n");
    Source += QStringLiteral("    var OrigLog = console.log;\n");
    Source += QStringLiteral("    var OrigWarn = console.warn;\n");
    Source += QStringLiteral("    var OrigError = console.error;\n");
    Source += QStringLiteral("    var OrigInfo = console.info;\n");
    Source += QStringLiteral("    var OrigDebug = console.debug;\n\n");

    Source += QStringLiteral("    function Stringify(Args) {\n");
    Source += QStringLiteral("        var Parts = [];\n");
    Source += QStringLiteral("        for (var I = 0; I < Args.length; I++) {\n");
    Source += QStringLiteral("            try {\n");
    Source += QStringLiteral("                if (typeof Args[I] === 'object') {\n");
    Source += QStringLiteral("                    Parts.push(JSON.stringify(Args[I], null, 2));\n");
    Source += QStringLiteral("                } else {\n");
    Source += QStringLiteral("                    Parts.push(String(Args[I]));\n");
    Source += QStringLiteral("                }\n");
    Source += QStringLiteral("            } catch(E) {\n");
    Source += QStringLiteral("                Parts.push(String(Args[I]));\n");
    Source += QStringLiteral("            }\n");
    Source += QStringLiteral("        }\n");
    Source += QStringLiteral("        return Parts.join(' ');\n");
    Source += QStringLiteral("    }\n\n");

    Source += QStringLiteral("    console.log = function() {\n");
    Source += QStringLiteral("        OrigLog.apply(console, arguments);\n");
    Source += QStringLiteral("        document.title = 'FIDRA_CONSOLE:log:' + Stringify(arguments);\n");
    Source += QStringLiteral("    };\n\n");

    Source += QStringLiteral("    console.warn = function() {\n");
    Source += QStringLiteral("        OrigWarn.apply(console, arguments);\n");
    Source += QStringLiteral("        document.title = 'FIDRA_CONSOLE:warn:' + Stringify(arguments);\n");
    Source += QStringLiteral("    };\n\n");

    Source += QStringLiteral("    console.error = function() {\n");
    Source += QStringLiteral("        OrigError.apply(console, arguments);\n");
    Source += QStringLiteral("        document.title = 'FIDRA_CONSOLE:error:' + Stringify(arguments);\n");
    Source += QStringLiteral("    };\n\n");

    Source += QStringLiteral("    console.info = function() {\n");
    Source += QStringLiteral("        OrigInfo.apply(console, arguments);\n");
    Source += QStringLiteral("        document.title = 'FIDRA_CONSOLE:info:' + Stringify(arguments);\n");
    Source += QStringLiteral("    };\n\n");

    Source += QStringLiteral("    console.debug = function() {\n");
    Source += QStringLiteral("        OrigDebug.apply(console, arguments);\n");
    Source += QStringLiteral("        document.title = 'FIDRA_CONSOLE:debug:' + Stringify(arguments);\n");
    Source += QStringLiteral("    };\n");

    Source += QStringLiteral("})();\n");

    InjectScript(CreateScript(QStringLiteral("FidraConsoleHook"), Source, QWebEngineScript::DocumentCreation));
}

void JsInjector::InjectXhrHook() {
    QString Source;
    Source += QStringLiteral("(function() {\n");
    Source += QStringLiteral("    var OrigOpen = XMLHttpRequest.prototype.open;\n");
    Source += QStringLiteral("    var OrigSend = XMLHttpRequest.prototype.send;\n\n");

    Source += QStringLiteral("    XMLHttpRequest.prototype.open = function(Method, Url) {\n");
    Source += QStringLiteral("        this._fidraMethod = Method;\n");
    Source += QStringLiteral("        this._fidraUrl = Url;\n");
    Source += QStringLiteral("        return OrigOpen.apply(this, arguments);\n");
    Source += QStringLiteral("    };\n\n");

    Source += QStringLiteral("    XMLHttpRequest.prototype.send = function(Body) {\n");
    Source += QStringLiteral("        var Self = this;\n");
    Source += QStringLiteral("        var OrigOnLoad = this.onload;\n");
    Source += QStringLiteral("        this.addEventListener('load', function() {\n");
    Source += QStringLiteral("            try {\n");
    Source += QStringLiteral("                var ResponseText = Self.responseText;\n");
    Source += QStringLiteral("                if (ResponseText && ResponseText.length > 4096) {\n");
    Source += QStringLiteral("                    ResponseText = ResponseText.substring(0, 4096) + '...[truncated]';\n");
    Source += QStringLiteral("                }\n");
    Source += QStringLiteral("                document.title = 'FIDRA_XHR:' + Self._fidraMethod + ':' + Self._fidraUrl + ':' + Self.status + ':' + ResponseText;\n");
    Source += QStringLiteral("            } catch(E) {}\n");
    Source += QStringLiteral("        });\n");
    Source += QStringLiteral("        return OrigSend.apply(this, arguments);\n");
    Source += QStringLiteral("    };\n");

    Source += QStringLiteral("})();\n");

    InjectScript(CreateScript(QStringLiteral("FidraXhrHook"), Source, QWebEngineScript::DocumentCreation));
}

void JsInjector::InjectFetchHook() {
    QString Source;
    Source += QStringLiteral("(function() {\n");
    Source += QStringLiteral("    var OrigFetch = window.fetch;\n\n");

    Source += QStringLiteral("    window.fetch = function(Input, Init) {\n");
    Source += QStringLiteral("        var Method = 'GET';\n");
    Source += QStringLiteral("        var Url = '';\n\n");

    Source += QStringLiteral("        if (typeof Input === 'string') {\n");
    Source += QStringLiteral("            Url = Input;\n");
    Source += QStringLiteral("        } else if (Input instanceof Request) {\n");
    Source += QStringLiteral("            Url = Input.url;\n");
    Source += QStringLiteral("            Method = Input.method;\n");
    Source += QStringLiteral("        }\n\n");

    Source += QStringLiteral("        if (Init && Init.method) {\n");
    Source += QStringLiteral("            Method = Init.method;\n");
    Source += QStringLiteral("        }\n\n");

    Source += QStringLiteral("        return OrigFetch.apply(this, arguments).then(function(Response) {\n");
    Source += QStringLiteral("            var ClonedResponse = Response.clone();\n");
    Source += QStringLiteral("            ClonedResponse.text().then(function(Body) {\n");
    Source += QStringLiteral("                try {\n");
    Source += QStringLiteral("                    if (Body && Body.length > 4096) {\n");
    Source += QStringLiteral("                        Body = Body.substring(0, 4096) + '...[truncated]';\n");
    Source += QStringLiteral("                    }\n");
    Source += QStringLiteral("                    document.title = 'FIDRA_FETCH:' + Method + ':' + Url + ':' + Response.status + ':' + Body;\n");
    Source += QStringLiteral("                } catch(E) {}\n");
    Source += QStringLiteral("            });\n");
    Source += QStringLiteral("            return Response;\n");
    Source += QStringLiteral("        });\n");
    Source += QStringLiteral("    };\n");

    Source += QStringLiteral("})();\n");

    InjectScript(CreateScript(QStringLiteral("FidraFetchHook"), Source, QWebEngineScript::DocumentCreation));
}

void JsInjector::InjectWebSocketHook() {
    QString Source;
    Source += QStringLiteral("(function() {\n");
    Source += QStringLiteral("    var OrigWebSocket = window.WebSocket;\n\n");

    Source += QStringLiteral("    window.WebSocket = function(Url, Protocols) {\n");
    Source += QStringLiteral("        var Ws;\n");
    Source += QStringLiteral("        if (Protocols) {\n");
    Source += QStringLiteral("            Ws = new OrigWebSocket(Url, Protocols);\n");
    Source += QStringLiteral("        } else {\n");
    Source += QStringLiteral("            Ws = new OrigWebSocket(Url);\n");
    Source += QStringLiteral("        }\n\n");

    Source += QStringLiteral("        var OrigSend = Ws.send.bind(Ws);\n");
    Source += QStringLiteral("        Ws.send = function(Data) {\n");
    Source += QStringLiteral("            try {\n");
    Source += QStringLiteral("                var Msg = typeof Data === 'string' ? Data : '[binary]';\n");
    Source += QStringLiteral("                if (Msg.length > 2048) Msg = Msg.substring(0, 2048) + '...[truncated]';\n");
    Source += QStringLiteral("                document.title = 'FIDRA_WS:' + Url + ':send:' + Msg;\n");
    Source += QStringLiteral("            } catch(E) {}\n");
    Source += QStringLiteral("            return OrigSend(Data);\n");
    Source += QStringLiteral("        };\n\n");

    Source += QStringLiteral("        Ws.addEventListener('message', function(Event) {\n");
    Source += QStringLiteral("            try {\n");
    Source += QStringLiteral("                var Msg = typeof Event.data === 'string' ? Event.data : '[binary]';\n");
    Source += QStringLiteral("                if (Msg.length > 2048) Msg = Msg.substring(0, 2048) + '...[truncated]';\n");
    Source += QStringLiteral("                document.title = 'FIDRA_WS:' + Url + ':recv:' + Msg;\n");
    Source += QStringLiteral("            } catch(E) {}\n");
    Source += QStringLiteral("        });\n\n");

    Source += QStringLiteral("        return Ws;\n");
    Source += QStringLiteral("    };\n\n");

    Source += QStringLiteral("    window.WebSocket.prototype = OrigWebSocket.prototype;\n");
    Source += QStringLiteral("    window.WebSocket.CONNECTING = OrigWebSocket.CONNECTING;\n");
    Source += QStringLiteral("    window.WebSocket.OPEN = OrigWebSocket.OPEN;\n");
    Source += QStringLiteral("    window.WebSocket.CLOSING = OrigWebSocket.CLOSING;\n");
    Source += QStringLiteral("    window.WebSocket.CLOSED = OrigWebSocket.CLOSED;\n");

    Source += QStringLiteral("})();\n");

    InjectScript(CreateScript(QStringLiteral("FidraWebSocketHook"), Source, QWebEngineScript::DocumentCreation));
}

void JsInjector::InjectAllHooks() {
    InjectConsoleHook();
    InjectXhrHook();
    InjectFetchHook();
    InjectWebSocketHook();
}

void JsInjector::AddUserScript(const UserScript& Script) {
    for (int I = 0; I < UserScripts.size(); I++) {
        if (UserScripts[I].Name == Script.Name) {
            UserScripts[I] = Script;
            ReloadUserScripts();
            return;
        }
    }
    UserScripts.append(Script);
    ReloadUserScripts();
}

void JsInjector::RemoveUserScript(const QString& Name) {
    for (int I = 0; I < UserScripts.size(); I++) {
        if (UserScripts[I].Name == Name) {
            UserScripts.removeAt(I);
            break;
        }
    }

    auto ExistingList = TargetProfile->scripts()->find(QStringLiteral("FidraUser_") + Name);
    for (const auto& Existing : ExistingList) {
        TargetProfile->scripts()->remove(Existing);
    }
}

void JsInjector::UpdateUserScript(const UserScript& Script) {
    for (int I = 0; I < UserScripts.size(); I++) {
        if (UserScripts[I].Name == Script.Name) {
            UserScripts[I] = Script;
            ReloadUserScripts();
            return;
        }
    }
}

QList<UserScript> JsInjector::GetUserScripts() const {
    return UserScripts;
}

void JsInjector::ShowScriptEditor(QWidget* Parent) {
    QDialog* ManagerDialog = new QDialog(Parent);
    ManagerDialog->setWindowTitle(QStringLiteral("User Scripts"));
    ManagerDialog->setMinimumSize(700, 500);
    ManagerDialog->setAttribute(Qt::WA_DeleteOnClose);

    QVBoxLayout* Layout = new QVBoxLayout(ManagerDialog);

    QSplitter* Splitter = new QSplitter(Qt::Horizontal, ManagerDialog);

    QWidget* ListPanel = new QWidget(Splitter);
    QVBoxLayout* ListLayout = new QVBoxLayout(ListPanel);
    ListLayout->setContentsMargins(0, 0, 0, 0);

    QListWidget* ScriptList = new QListWidget(ListPanel);
    ListLayout->addWidget(ScriptList);

    QHBoxLayout* ListButtonLayout = new QHBoxLayout();
    QPushButton* AddButton = new QPushButton(QStringLiteral("Add"), ListPanel);
    QPushButton* RemoveButton = new QPushButton(QStringLiteral("Remove"), ListPanel);
    ListButtonLayout->addWidget(AddButton);
    ListButtonLayout->addWidget(RemoveButton);
    ListLayout->addLayout(ListButtonLayout);

    Splitter->addWidget(ListPanel);

    QWidget* EditorPanel = new QWidget(Splitter);
    QVBoxLayout* EditorLayout = new QVBoxLayout(EditorPanel);
    EditorLayout->setContentsMargins(0, 0, 0, 0);

    QHBoxLayout* EditorNameLayout = new QHBoxLayout();
    QLabel* NameLabel = new QLabel(QStringLiteral("Name:"), EditorPanel);
    QLineEdit* NameEdit = new QLineEdit(EditorPanel);
    EditorNameLayout->addWidget(NameLabel);
    EditorNameLayout->addWidget(NameEdit);
    EditorLayout->addLayout(EditorNameLayout);

    QHBoxLayout* EditorOptionsLayout = new QHBoxLayout();
    QLabel* InjLabel = new QLabel(QStringLiteral("Inject at:"), EditorPanel);
    QComboBox* InjCombo = new QComboBox(EditorPanel);
    InjCombo->addItem(QStringLiteral("Document Creation"), QWebEngineScript::DocumentCreation);
    InjCombo->addItem(QStringLiteral("Document Ready"), QWebEngineScript::DocumentReady);
    InjCombo->addItem(QStringLiteral("Deferred"), QWebEngineScript::Deferred);
    QCheckBox* EnabledCheck = new QCheckBox(QStringLiteral("Enabled"), EditorPanel);
    EnabledCheck->setChecked(true);
    EditorOptionsLayout->addWidget(InjLabel);
    EditorOptionsLayout->addWidget(InjCombo);
    EditorOptionsLayout->addStretch();
    EditorOptionsLayout->addWidget(EnabledCheck);
    EditorLayout->addLayout(EditorOptionsLayout);

    QPlainTextEdit* CodeEdit = new QPlainTextEdit(EditorPanel);
    CodeEdit->setFont(QFont(QStringLiteral("Consolas"), 10));
    CodeEdit->setTabStopDistance(28);
    EditorLayout->addWidget(CodeEdit, 1);

    QPushButton* SaveButton = new QPushButton(QStringLiteral("Save Script"), EditorPanel);
    EditorLayout->addWidget(SaveButton);

    Splitter->addWidget(EditorPanel);
    Splitter->setStretchFactor(0, 1);
    Splitter->setStretchFactor(1, 3);

    Layout->addWidget(Splitter);

    for (const auto& Us : UserScripts) {
        QListWidgetItem* Item = new QListWidgetItem(Us.Name);
        Item->setCheckState(Us.Enabled ? Qt::Checked : Qt::Unchecked);
        ScriptList->addItem(Item);
    }

    connect(ScriptList, &QListWidget::currentRowChanged, this, [this, ScriptList, NameEdit, CodeEdit, InjCombo, EnabledCheck](int Row) {
        if (Row < 0 || Row >= UserScripts.size()) return;
        const UserScript& Us = UserScripts[Row];
        NameEdit->setText(Us.Name);
        CodeEdit->setPlainText(Us.Code);
        EnabledCheck->setChecked(Us.Enabled);
        for (int I = 0; I < InjCombo->count(); I++) {
            if (InjCombo->itemData(I).toInt() == Us.InjectionPoint) {
                InjCombo->setCurrentIndex(I);
                break;
            }
        }
    });

    connect(AddButton, &QPushButton::clicked, this, [this, ScriptList, NameEdit, CodeEdit, EnabledCheck, InjCombo]() {
        UserScript NewScript;
        NewScript.Name = QStringLiteral("NewScript_%1").arg(UserScripts.size());
        NewScript.Code = QStringLiteral("(function() {\n\n})();");
        NewScript.Enabled = true;
        NewScript.InjectionPoint = QWebEngineScript::DocumentReady;
        NewScript.WorldId = 0;

        UserScripts.append(NewScript);

        QListWidgetItem* Item = new QListWidgetItem(NewScript.Name);
        Item->setCheckState(Qt::Checked);
        ScriptList->addItem(Item);
        ScriptList->setCurrentRow(ScriptList->count() - 1);

        NameEdit->setText(NewScript.Name);
        CodeEdit->setPlainText(NewScript.Code);
        EnabledCheck->setChecked(true);
    });

    connect(RemoveButton, &QPushButton::clicked, this, [this, ScriptList]() {
        int Row = ScriptList->currentRow();
        if (Row < 0 || Row >= UserScripts.size()) return;

        QString ScriptName = UserScripts[Row].Name;
        RemoveUserScript(ScriptName);
        delete ScriptList->takeItem(Row);
    });

    connect(SaveButton, &QPushButton::clicked, this, [this, ScriptList, NameEdit, CodeEdit, InjCombo, EnabledCheck]() {
        int Row = ScriptList->currentRow();
        if (Row < 0 || Row >= UserScripts.size()) return;

        UserScripts[Row].Name = NameEdit->text();
        UserScripts[Row].Code = CodeEdit->toPlainText();
        UserScripts[Row].Enabled = EnabledCheck->isChecked();
        UserScripts[Row].InjectionPoint = static_cast<QWebEngineScript::InjectionPoint>(
            InjCombo->currentData().toInt());

        ScriptList->item(Row)->setText(NameEdit->text());
        ScriptList->item(Row)->setCheckState(EnabledCheck->isChecked() ? Qt::Checked : Qt::Unchecked);

        ReloadUserScripts();
    });

    ManagerDialog->exec();
}

QWebEngineScript JsInjector::CreateScript(const QString& Name, const QString& Source, QWebEngineScript::InjectionPoint Point, int WorldId) {
    QWebEngineScript Script;
    Script.setName(Name);
    Script.setSourceCode(Source);
    Script.setInjectionPoint(Point);
    Script.setWorldId(WorldId);
    Script.setRunsOnSubFrames(true);
    return Script;
}

void JsInjector::ReloadUserScripts() {
    QWebEngineScriptCollection* Scripts = TargetProfile->scripts();

    for (const auto& Us : UserScripts) {
        QString FullName = QStringLiteral("FidraUser_") + Us.Name;
        auto ExistingList = Scripts->find(FullName);
        for (const auto& Existing : ExistingList) {
            Scripts->remove(Existing);
        }
    }

    for (const auto& Us : UserScripts) {
        if (!Us.Enabled) continue;
        QString FullName = QStringLiteral("FidraUser_") + Us.Name;
        QWebEngineScript Script = CreateScript(FullName, Us.Code, Us.InjectionPoint, Us.WorldId);
        Scripts->insert(Script);
    }
}

}
