#include "Theme.h"
#include <QPalette>
#include <QFont>
#include <QFile>

namespace Fidra {

void Theme::Apply(QApplication* App) {
    App->setStyle("Fusion");

    QPalette DarkPalette;
    DarkPalette.setColor(QPalette::Window, QColor(30, 30, 30));
    DarkPalette.setColor(QPalette::WindowText, QColor(212, 212, 212));
    DarkPalette.setColor(QPalette::Base, QColor(25, 25, 25));
    DarkPalette.setColor(QPalette::AlternateBase, QColor(35, 35, 35));
    DarkPalette.setColor(QPalette::ToolTipBase, QColor(45, 45, 45));
    DarkPalette.setColor(QPalette::ToolTipText, QColor(212, 212, 212));
    DarkPalette.setColor(QPalette::Text, QColor(212, 212, 212));
    DarkPalette.setColor(QPalette::Button, QColor(45, 45, 45));
    DarkPalette.setColor(QPalette::ButtonText, QColor(212, 212, 212));
    DarkPalette.setColor(QPalette::BrightText, QColor(255, 255, 255));
    DarkPalette.setColor(QPalette::Link, QColor(86, 156, 214));
    DarkPalette.setColor(QPalette::Highlight, QColor(38, 79, 120));
    DarkPalette.setColor(QPalette::HighlightedText, QColor(255, 255, 255));
    DarkPalette.setColor(QPalette::Disabled, QPalette::Text, QColor(128, 128, 128));
    DarkPalette.setColor(QPalette::Disabled, QPalette::ButtonText, QColor(128, 128, 128));
    DarkPalette.setColor(QPalette::Disabled, QPalette::HighlightedText, QColor(128, 128, 128));

    App->setPalette(DarkPalette);
    App->setStyleSheet(GetStyleSheet());
}

QString Theme::GetStyleSheet() {
    return R"(
        QMainWindow {
            background-color: #1e1e1e;
        }
        QMenuBar {
            background-color: #2d2d2d;
            border-bottom: 1px solid #3e3e3e;
            padding: 2px;
        }
        QMenuBar::item {
            padding: 4px 8px;
            background: transparent;
        }
        QMenuBar::item:selected {
            background-color: #094771;
            border-radius: 3px;
        }
        QMenu {
            background-color: #2d2d2d;
            border: 1px solid #3e3e3e;
            padding: 4px;
        }
        QMenu::item {
            padding: 6px 24px 6px 12px;
        }
        QMenu::item:selected {
            background-color: #094771;
        }
        QMenu::separator {
            height: 1px;
            background: #3e3e3e;
            margin: 4px 8px;
        }
        QToolBar {
            background-color: #2d2d2d;
            border-bottom: 1px solid #3e3e3e;
            padding: 2px;
            spacing: 2px;
        }
        QToolButton {
            background: transparent;
            border: 1px solid transparent;
            border-radius: 3px;
            padding: 4px;
        }
        QToolButton:hover {
            background-color: #3e3e3e;
            border-color: #4e4e4e;
        }
        QToolButton:pressed {
            background-color: #094771;
        }
        QTabWidget::pane {
            border: 1px solid #3e3e3e;
            background-color: #1e1e1e;
        }
        QTabBar::tab {
            background-color: #2d2d2d;
            color: #9d9d9d;
            padding: 8px 16px;
            border: 1px solid #3e3e3e;
            border-bottom: none;
            margin-right: 1px;
        }
        QTabBar::tab:selected {
            background-color: #1e1e1e;
            color: #ffffff;
            border-bottom: 2px solid #569cd6;
        }
        QTabBar::tab:hover:!selected {
            background-color: #353535;
            color: #cccccc;
        }
        QDockWidget {
            titlebar-close-icon: none;
            titlebar-normal-icon: none;
        }
        QDockWidget::title {
            background-color: #2d2d2d;
            border: 1px solid #3e3e3e;
            padding: 6px;
            text-align: left;
        }
        QStatusBar {
            background-color: #007acc;
            color: white;
        }
        QStatusBar::item {
            border: none;
        }
        QStatusBar QLabel {
            color: white;
            padding: 0 8px;
        }
        QTableWidget, QTableView, QTreeWidget, QTreeView, QListWidget, QListView {
            background-color: #1e1e1e;
            alternate-background-color: #252525;
            border: 1px solid #3e3e3e;
            gridline-color: #2d2d2d;
            selection-background-color: #094771;
        }
        QHeaderView::section {
            background-color: #2d2d2d;
            color: #cccccc;
            padding: 4px 8px;
            border: none;
            border-right: 1px solid #3e3e3e;
            border-bottom: 1px solid #3e3e3e;
        }
        QScrollBar:vertical {
            background-color: #1e1e1e;
            width: 12px;
            margin: 0;
        }
        QScrollBar::handle:vertical {
            background-color: #424242;
            min-height: 20px;
            border-radius: 3px;
            margin: 2px;
        }
        QScrollBar::handle:vertical:hover {
            background-color: #525252;
        }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
            height: 0;
        }
        QScrollBar:horizontal {
            background-color: #1e1e1e;
            height: 12px;
            margin: 0;
        }
        QScrollBar::handle:horizontal {
            background-color: #424242;
            min-width: 20px;
            border-radius: 3px;
            margin: 2px;
        }
        QScrollBar::handle:horizontal:hover {
            background-color: #525252;
        }
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
            width: 0;
        }
        QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QDoubleSpinBox, QComboBox {
            background-color: #2d2d2d;
            border: 1px solid #3e3e3e;
            border-radius: 3px;
            padding: 4px;
            color: #cccccc;
            selection-background-color: #094771;
        }
        QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {
            border-color: #569cd6;
        }
        QPushButton {
            background-color: #0e639c;
            color: white;
            border: none;
            border-radius: 3px;
            padding: 6px 14px;
        }
        QPushButton:hover {
            background-color: #1177bb;
        }
        QPushButton:pressed {
            background-color: #094771;
        }
        QPushButton:disabled {
            background-color: #3e3e3e;
            color: #888888;
        }
        QSplitter::handle {
            background-color: #3e3e3e;
        }
        QSplitter::handle:horizontal {
            width: 2px;
        }
        QSplitter::handle:vertical {
            height: 2px;
        }
        QGroupBox {
            border: 1px solid #3e3e3e;
            border-radius: 4px;
            margin-top: 8px;
            padding-top: 8px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            padding: 0 4px;
            color: #cccccc;
        }
        QCheckBox::indicator, QRadioButton::indicator {
            width: 14px;
            height: 14px;
        }
        QProgressBar {
            border: 1px solid #3e3e3e;
            border-radius: 3px;
            text-align: center;
            background-color: #2d2d2d;
        }
        QProgressBar::chunk {
            background-color: #0e639c;
            border-radius: 2px;
        }
        QToolTip {
            background-color: #2d2d2d;
            color: #cccccc;
            border: 1px solid #3e3e3e;
            padding: 4px;
        }
    )";
}

}
