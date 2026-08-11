#pragma once

#include "DiffEngine.h"
#include <fidra/ICore.h>
#include <QWidget>
#include <QTableWidget>
#include <QPlainTextEdit>
#include <QTextEdit>
#include <QTabWidget>
#include <QProgressBar>
#include <QLabel>
#include <QPushButton>
#include <QLineEdit>
#include <QComboBox>
#include <QCheckBox>
#include <QSplitter>

namespace Fidra {

class DiffWidget : public QWidget {
    Q_OBJECT

public:
    explicit DiffWidget(QWidget* Parent = nullptr, ICore* Core = nullptr);

    void CompareFiles(const QString& OldPath, const QString& NewPath);

signals:
    void StatusMessage(const QString& Message);

private slots:
    void OnBrowseOld();
    void OnBrowseNew();
    void OnRunDiff();
    void OnFilterChanged();
    void OnPrevDiff();
    void OnNextDiff();
    void OnFunctionTableClicked(int Row, int Column);

private:
    ICore* CoreRef;
    DiffEngine* Engine;
    DiffResult CurrentResult;

    QLineEdit* OldFileEdit;
    QLineEdit* NewFileEdit;
    QPushButton* BrowseOldButton;
    QPushButton* BrowseNewButton;
    QPushButton* RunButton;
    QComboBox* FilterCombo;
    QCheckBox* ShowUnchangedCheck;

    QPushButton* PrevDiffButton;
    QPushButton* NextDiffButton;
    QLabel* DiffNavLabel;
    int CurrentDiffIndex;

    QTabWidget* ResultTabs;
    QTableWidget* FunctionTable;
    QTextEdit* SummaryText;
    QPlainTextEdit* OldHexEdit;
    QPlainTextEdit* NewHexEdit;
    QSplitter* HexSplitter;
    QTableWidget* ByteTable;

    QProgressBar* ProgressBar;
    QLabel* StatusLabel;

    QLabel* StatsChangedLabel;
    QLabel* StatsAddedLabel;
    QLabel* StatsRemovedLabel;
    QLabel* StatsSimilarityLabel;

    void SetupUi();
    void PopulateFunctionTable();
    void PopulateByteTable();
    void PopulateSummary();
    void UpdateHexView();
    void HighlightHexDiffs();
    void ScrollToByteOffset(int64_t Offset);
    void UpdateDiffNavLabel();
    QString FormatHexDump(const QByteArray& Data, int BytesPerLine = 16);

    QByteArray OldFileData;
    QByteArray NewFileData;

    QVector<int64_t> DiffOffsets;
};

}
