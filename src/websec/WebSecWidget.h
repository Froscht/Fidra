#pragma once

#include <fidra/Types.h>
#include <fidra/ICore.h>
#include <QWidget>
#include <QTabWidget>
#include <QTableWidget>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QLabel>
#include <QSpinBox>
#include <QSplitter>

namespace Fidra {

class HttpProxy;
class RepeaterWidget;
class IntruderWidget;
class DecoderWidget;

class WebSecWidget : public QWidget {
    Q_OBJECT

public:
    explicit WebSecWidget(QWidget* Parent = nullptr);
    ~WebSecWidget() override;

    void SetCore(ICore* Core);
    void StopProxy();
    void ToggleProxy();
    void AddRepeaterTab();

private slots:
    void OnProxyToggle();
    void OnRequestCaptured(const HttpRequest& Request);
    void OnHistoryItemSelected();
    void OnSendToRepeater();
    void OnSendToIntruder();
    void OnClearHistory();

private:
    void SetupProxyTab();
    void SetupRepeaterTab();
    void SetupIntruderTab();
    void SetupDecoderTab();
    void UpdateHistoryTable(const HttpRequest& Request);

    ICore* CoreRef;
    QTabWidget* MainTabs;

    QWidget* ProxyTab;
    HttpProxy* Proxy;
    QTableWidget* HistoryTable;
    QPlainTextEdit* RequestViewer;
    QPlainTextEdit* ResponseViewer;
    QPushButton* ProxyToggleButton;
    QSpinBox* PortSpinBox;
    QLabel* ProxyStatusLabel;

    RepeaterWidget* Repeater;
    IntruderWidget* Intruder;
    DecoderWidget* Decoder;

    QList<HttpRequest> DisplayedHistory;
};

}
