from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable

from PySide6.QtCore import Qt, QThread, Signal, QUrl
from PySide6.QtGui import QAction, QColor, QDesktopServices
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListView,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QProgressBar,
    QScrollArea,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

try:
    from send2trash import send2trash
except Exception:
    send2trash = None


APP_NAME = "Mac Space Guard"

DEFAULT_SCAN_TARGETS = [
    Path.home() / "Library" / "Application Support",
    Path.home() / "Library" / "Containers",
    Path.home() / "Library" / "Group Containers",
    Path.home() / "Library" / "Android",
    Path.home() / "Downloads",
    Path.home() / "Pictures",
]

PROTECTED_PATH_HINTS = [
    "/Library/Containers/",
    "/Library/Group Containers/",
]


@dataclass
class ScanResult:
    path: Path
    size_bytes: int
    category: str
    safety: str
    note: str
    action_hint: str
    source_root: str


RULES: dict[str, tuple[str, str, str, str]] = {
    "Google": (
        "Browser",
        "Revisar",
        "Pode conter perfil, cache e sessão do navegador.",
        "Feche Chrome/Arc antes de limpar para evitar falhas.",
    ),
    "Chrome": (
        "Browser",
        "Revisar",
        "Pode conter perfil, cache e sessão do navegador.",
        "Feche Chrome antes de limpar.",
    ),
    "Arc": (
        "Browser",
        "Revisar",
        "Pode conter perfil, cache e sessão do navegador.",
        "Feche Arc antes de limpar.",
    ),
    "Code": (
        "IDE",
        "Seguro",
        "Normalmente contém cache e dados do VS Code.",
        "Baixo risco na maioria dos casos.",
    ),
    "Cursor": (
        "IDE",
        "Seguro",
        "Geralmente contém cache e dados do editor.",
        "Baixo risco na maioria dos casos.",
    ),
    "Notion": (
        "Produtividade",
        "Seguro",
        "Cache offline pode crescer bastante.",
        "Fechar Notion antes de limpar melhora a chance de sucesso.",
    ),
    "discord": (
        "Chat",
        "Seguro",
        "Cache e mídia local costumam crescer com o tempo.",
        "Feche Discord antes de limpar.",
    ),
    "Telegram": (
        "Chat",
        "Revisar",
        "Pode conter mídia baixada localmente.",
        "Feche Telegram antes de limpar.",
    ),
    "WhatsApp": (
        "Chat",
        "Revisar",
        "Pode conter mídia e sessão local.",
        "Feche WhatsApp antes de limpar.",
    ),
    "Docker": (
        "Dev",
        "Revisar",
        "Pode incluir imagens, volumes e containers.",
        "Considere fechar Docker Desktop ou usar docker system prune.",
    ),
    "Android": (
        "Dev",
        "Revisar",
        "Pode conter SDK, AVD e builds.",
        "Revise se há emuladores ou SDKs ainda necessários.",
    ),
    "pyinstaller": (
        "Dev",
        "Seguro",
        "Artefatos de build antigos.",
        "Baixo risco na maioria dos casos.",
    ),
    "Postman": (
        "Dev",
        "Revisar",
        "Pode conter coleções, cache local e dados de sessão.",
        "Revise antes de excluir se usa ambientes locais.",
    ),
    "TabNine": (
        "Dev",
        "Seguro",
        "Cache de modelos e dados locais do editor.",
        "Baixo risco na maioria dos casos.",
    ),
    "OpenEmu": (
        "Emulação",
        "Revisar",
        "Pode conter ROMs, saves e BIOS.",
        "Revise manualmente antes de excluir.",
    ),
    "minecraft": (
        "Jogos",
        "Revisar",
        "Pode conter mundos, mods e saves.",
        "Revise manualmente antes de excluir.",
    ),
    "com.apple.wallpaper": (
        "Sistema",
        "Seguro",
        "Cache local de wallpapers.",
        "Baixo risco na maioria dos casos.",
    ),
    "Caches": (
        "Cache/Logs",
        "Seguro",
        "Itens geralmente recuperáveis.",
        "Baixo risco na maioria dos casos.",
    ),
    "Logs": (
        "Cache/Logs",
        "Seguro",
        "Logs antigos costumam ser recuperáveis.",
        "Baixo risco na maioria dos casos.",
    ),
}


def format_bytes(num: int) -> str:
    value = float(num)
    for unit in ["B", "KB", "MB", "GB", "TB", "PB"]:
        if value < 1024:
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} EB"


def classify(path: Path) -> tuple[str, str, str, str]:
    name = path.name
    for key, value in RULES.items():
        if key.lower() in name.lower():
            return value

    lowered = str(path).lower()
    if "cache" in lowered or "logs" in lowered:
        return (
            "Cache/Logs",
            "Seguro",
            "Itens geralmente recuperáveis.",
            "Baixo risco na maioria dos casos.",
        )
    if "container" in lowered:
        return (
            "Containers",
            "Revisar",
            "Pode conter dados persistidos de apps.",
            "Pode exigir fechar o app relacionado e conceder Acesso Total ao Disco.",
        )
    if lowered.endswith(".photoslibrary"):
        return (
            "Fotos",
            "Revisar",
            "Biblioteca de fotos local do macOS.",
            "Revise manualmente antes de excluir.",
        )
    if "download" in lowered:
        return (
            "Downloads",
            "Revisar",
            "Pode conter instaladores, vídeos e arquivos temporários.",
            "Revise antes de remover em massa.",
        )
    return (
        "Outros",
        "Revisar",
        "Revise antes de limpar.",
        "Valide antes de remover.",
    )


class SizeTableWidgetItem(QTableWidgetItem):
    def __init__(self, size_bytes: int):
        super().__init__(format_bytes(size_bytes))
        self.size_bytes = size_bytes
        self.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)

    def __lt__(self, other):
        if isinstance(other, SizeTableWidgetItem):
            return self.size_bytes < other.size_bytes
        return super().__lt__(other)


class ScannerThread(QThread):
    progress = Signal(int)
    finished_scan = Signal(list)
    failed = Signal(str)

    def __init__(self, targets: Iterable[Path]):
        super().__init__()
        self.targets = [target for target in targets if target.exists()]

    def run(self) -> None:
        try:
            results: list[ScanResult] = []
            if not self.targets:
                self.finished_scan.emit(results)
                return

            total_targets = len(self.targets)
            for index, target in enumerate(self.targets, start=1):
                children = list(self.safe_iterdir(target))
                for child in children:
                    size = self.get_size(child)
                    category, safety, note, action_hint = classify(child)
                    results.append(
                        ScanResult(
                            path=child,
                            size_bytes=size,
                            category=category,
                            safety=safety,
                            note=note,
                            action_hint=action_hint,
                            source_root=str(target),
                        )
                    )
                self.progress.emit(int(index / total_targets * 100))

            results.sort(key=lambda item: item.size_bytes, reverse=True)
            self.finished_scan.emit(results)
        except Exception as exc:
            self.failed.emit(str(exc))

    def safe_iterdir(self, path: Path) -> Iterable[Path]:
        try:
            yield from path.iterdir()
        except (PermissionError, FileNotFoundError, OSError):
            return

    def get_size(self, path: Path) -> int:
        try:
            if path.is_symlink():
                return 0
            if path.is_file():
                return path.stat().st_size

            total = 0
            for root, dirs, files in os.walk(path, onerror=lambda e: None):
                dirs[:] = [d for d in dirs if not Path(root, d).is_symlink()]
                for file_name in files:
                    file_path = Path(root) / file_name
                    try:
                        if not file_path.is_symlink():
                            total += file_path.stat().st_size
                    except (PermissionError, FileNotFoundError, OSError):
                        continue
            return total
        except (PermissionError, FileNotFoundError, OSError):
            return 0


class StatCard(QFrame):
    def __init__(self, title: str, value: str, subtitle: str = ""):
        super().__init__()
        self.setObjectName("statCard")

        self.title_label = QLabel(title)
        self.title_label.setObjectName("cardTitle")
        self.title_label.setStyleSheet("background: transparent;")

        self.value_label = QLabel(value)
        self.value_label.setObjectName("cardValue")
        self.value_label.setStyleSheet("background: transparent;")

        self.subtitle_label = QLabel(subtitle)
        self.subtitle_label.setObjectName("cardSubtitle")
        self.subtitle_label.setWordWrap(True)
        self.subtitle_label.setStyleSheet("background: transparent;")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(6)
        layout.addWidget(self.title_label)
        layout.addWidget(self.value_label)
        layout.addWidget(self.subtitle_label)

    def update_content(self, value: str, subtitle: str = "") -> None:
        self.value_label.setText(value)
        self.subtitle_label.setText(subtitle)


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.resize(1540, 920)

        self.results: list[ScanResult] = []
        self.filtered_results: list[ScanResult] = []
        self.thread: ScannerThread | None = None
        self.last_scan_timestamp: str = "Ainda não executado"

        self.build_ui()
        self.apply_styles()
        self.switch_page("dashboard")

    def build_ui(self) -> None:
        self.status_label = QLabel("Pronto para escanear.")
        self.status_label.setObjectName("statusLabel")

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setTextVisible(False)

        self.total_card = StatCard(
            "Espaço analisado",
            "0 B",
            "Volume total dos itens exibidos atualmente.",
        )
        self.safe_card = StatCard(
            "Seguro",
            "0 B",
            "Itens com baixo risco para limpeza.",
        )
        self.review_card = StatCard(
            "Revisar",
            "0 B",
            "Itens que exigem conferência manual.",
        )
        self.items_card = StatCard(
            "Itens encontrados",
            "0",
            "Quantidade de entradas após filtros.",
        )

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Buscar por nome, caminho ou app...")
        self.search_input.textChanged.connect(self.apply_filters)

        self.safety_filter = QComboBox()
        self.safety_filter.addItems(["Todos", "Seguro", "Revisar"])
        self.safety_filter.currentTextChanged.connect(self.apply_filters)

        self.category_filter = QComboBox()
        self.category_filter.addItem("Todas")
        self.category_filter.currentTextChanged.connect(self.apply_filters)

        self.size_filter = QComboBox()
        self.size_filter.addItems(["Todos", "> 100 MB", "> 500 MB", "> 1 GB", "> 5 GB"])
        self.size_filter.currentTextChanged.connect(self.apply_filters)

        for combo in [self.safety_filter, self.category_filter, self.size_filter]:
            combo.setView(QListView())
            combo.setMaxVisibleItems(6)
            combo.setMinimumHeight(36)
            combo.view().setSpacing(0)
            combo.view().setUniformItemSizes(True)

        self.safety_filter.setFixedWidth(95)
        self.category_filter.setFixedWidth(120)
        self.size_filter.setFixedWidth(110)

        self.insights_label = QLabel("Faça um escaneamento para ver os maiores vilões do disco.")
        self.insights_label.setObjectName("insightsLabel")
        self.insights_label.setWordWrap(True)
        self.insights_label.setAlignment(Qt.AlignTop | Qt.AlignLeft)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["Arquivo", "Tamanho", "Categoria", "Status", "Observação", "Sugestão"]
        )
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSortingEnabled(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setColumnWidth(0, 470)
        self.table.setColumnWidth(1, 110)
        self.table.setColumnWidth(2, 120)
        self.table.setColumnWidth(3, 110)
        self.table.setColumnWidth(4, 280)
        self.table.setColumnWidth(5, 290)

        self.header_title = QLabel("Visualização de Espaço em Disco")
        self.header_title.setObjectName("pageTitle")

        self.header_subtitle = QLabel("Analise e libere espaço com segurança")
        self.header_subtitle.setObjectName("pageSubtitle")

        self.build_sidebar()
        self.build_pages()

        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(22, 22, 22, 22)
        content_layout.setSpacing(14)
        content_layout.addWidget(self.header_title)
        content_layout.addWidget(self.header_subtitle)
        content_layout.addWidget(self.stack)

        main_layout = QHBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        main_layout.addWidget(self.sidebar)
        main_layout.addWidget(content)

        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

        exit_action = QAction("Sair", self)
        exit_action.triggered.connect(self.close)
        self.menuBar().addAction(exit_action)

    def build_sidebar(self) -> None:
        self.sidebar = QFrame()
        self.sidebar.setObjectName("sidebar")
        self.sidebar.setFixedWidth(290)

        layout = QVBoxLayout(self.sidebar)
        layout.setContentsMargins(18, 20, 18, 20)
        layout.setSpacing(10)

        logo_label = QLabel("🚀  Mac Space Guard")
        logo_label.setObjectName("logoLabel")

        self.nav_dashboard = QPushButton("Dashboard")
        self.nav_clean = QPushButton("Smart Clean")
        self.nav_reports = QPushButton("Reports")
        self.nav_settings = QPushButton("Settings")

        for btn in [self.nav_dashboard, self.nav_clean, self.nav_reports, self.nav_settings]:
            btn.setCursor(Qt.PointingHandCursor)
            btn.setCheckable(True)
            btn.clicked.connect(self.handle_sidebar_click)

        layout.addWidget(logo_label)
        layout.addSpacing(18)
        layout.addWidget(self.nav_dashboard)
        layout.addWidget(self.nav_clean)
        layout.addWidget(self.nav_reports)
        layout.addWidget(self.nav_settings)
        layout.addStretch()

    def build_pages(self) -> None:
        self.stack = QStackedWidget()

        self.page_dashboard = self.build_dashboard_page()
        self.page_smart_clean = self.build_smart_clean_page()
        self.page_reports = self.build_reports_page()
        self.page_settings = self.build_settings_page()

        self.stack.addWidget(self.page_dashboard)
        self.stack.addWidget(self.page_smart_clean)
        self.stack.addWidget(self.page_reports)
        self.stack.addWidget(self.page_settings)

    def build_dashboard_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(14)

        scan_button = QPushButton("Escanear Disco")
        scan_button.clicked.connect(self.start_default_scan)

        custom_button = QPushButton("Escanear Pasta Específica...")
        custom_button.clicked.connect(self.scan_custom_folder)

        export_json_button = QPushButton("Exportar JSON")
        export_json_button.clicked.connect(self.export_json)

        reveal_button = QPushButton("Abrir no Finder")
        reveal_button.clicked.connect(self.reveal_selected)

        trash_button = QPushButton("Mover para Lixeira")
        trash_button.clicked.connect(self.trash_selected)

        smart_clean_button = QPushButton("Limpeza Inteligente com IA")
        smart_clean_button.setObjectName("primaryButton")
        smart_clean_button.clicked.connect(self.smart_clean_safe_items)

        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(12)
        cards_layout.addWidget(self.total_card)
        cards_layout.addWidget(self.safe_card)
        cards_layout.addWidget(self.review_card)
        cards_layout.addWidget(self.items_card)

        top_actions_layout = QHBoxLayout()
        top_actions_layout.addWidget(scan_button)
        top_actions_layout.addWidget(custom_button)
        top_actions_layout.addWidget(export_json_button)
        top_actions_layout.addStretch()
        top_actions_layout.addWidget(reveal_button)
        top_actions_layout.addWidget(trash_button)

        filters_bar = QHBoxLayout()
        filters_bar.setSpacing(10)
        filters_bar.addWidget(QLabel("Busca"))
        filters_bar.addWidget(self.search_input, 2)
        filters_bar.addWidget(QLabel("Status"))
        filters_bar.addWidget(self.safety_filter)
        filters_bar.addWidget(QLabel("Categoria"))
        filters_bar.addWidget(self.category_filter)
        filters_bar.addWidget(QLabel("Tamanho"))
        filters_bar.addWidget(self.size_filter)

        cta_layout = QHBoxLayout()
        cta_layout.addStretch()
        cta_layout.addWidget(smart_clean_button)
        cta_layout.addStretch()

        layout.addLayout(top_actions_layout)
        layout.addWidget(self.status_label)
        layout.addWidget(self.progress)
        layout.addLayout(cards_layout)
        layout.addLayout(filters_bar)
        layout.addWidget(self.table)
        layout.addLayout(cta_layout)
        return page

    def build_smart_clean_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(14)

        title = QLabel("Smart Clean")
        title.setObjectName("sectionTitle")

        subtitle = QLabel(
            "Revise rapidamente os itens seguros e execute a limpeza automática com um clique."
        )
        subtitle.setObjectName("sectionSubtitle")
        subtitle.setWordWrap(True)

        self.smart_safe_total_card = StatCard(
            "Espaço seguro recuperável",
            "0 B",
            "Estimativa baseada nos itens atualmente classificados como seguros.",
        )
        self.smart_safe_count_card = StatCard(
            "Itens seguros",
            "0",
            "Quantidade de entradas com baixo risco.",
        )
        self.smart_review_total_card = StatCard(
            "Itens para revisar",
            "0 B",
            "Itens que exigem análise manual antes da limpeza.",
        )

        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(12)
        cards_layout.addWidget(self.smart_safe_total_card)
        cards_layout.addWidget(self.smart_safe_count_card)
        cards_layout.addWidget(self.smart_review_total_card)

        self.smart_clean_text = QTextEdit()
        self.smart_clean_text.setReadOnly(True)
        self.smart_clean_text.setObjectName("smartCleanPanel")

        smart_clean_run_button = QPushButton("Executar Limpeza Inteligente com IA")
        smart_clean_run_button.setObjectName("primaryButton")
        smart_clean_run_button.clicked.connect(self.smart_clean_safe_items)

        refresh_button = QPushButton("Atualizar Resumo")
        refresh_button.clicked.connect(self.refresh_smart_clean_page)

        actions = QHBoxLayout()
        actions.addWidget(refresh_button)
        actions.addStretch()
        actions.addWidget(smart_clean_run_button)

        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addLayout(cards_layout)
        layout.addWidget(self.smart_clean_text)
        layout.addLayout(actions)
        return page

    def build_reports_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(14)

        title = QLabel("Reports")
        title.setObjectName("sectionTitle")

        subtitle = QLabel(
            "Resumo executivo do último escaneamento, pronto para validação e exportação."
        )
        subtitle.setObjectName("sectionSubtitle")
        subtitle.setWordWrap(True)

        self.report_last_scan_card = StatCard(
            "Último escaneamento",
            "—",
            "Data e hora da última execução.",
        )
        self.report_total_card = StatCard(
            "Total analisado",
            "0 B",
            "Volume total do conjunto atual.",
        )
        self.report_safe_card = StatCard(
            "Seguro",
            "0 B",
            "Volume estimado de itens seguros.",
        )
        self.report_top_category_card = StatCard(
            "Categoria mais pesada",
            "—",
            "Categoria com maior volume no scan atual.",
        )

        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(12)
        cards_layout.addWidget(self.report_last_scan_card)
        cards_layout.addWidget(self.report_total_card)
        cards_layout.addWidget(self.report_safe_card)
        cards_layout.addWidget(self.report_top_category_card)

        self.reports_text = QTextEdit()
        self.reports_text.setReadOnly(True)
        self.reports_text.setObjectName("reportsPanel")

        export_button = QPushButton("Exportar JSON")
        export_button.clicked.connect(self.export_json)

        go_insights_button = QPushButton("Ver Insights")
        go_insights_button.clicked.connect(lambda: self.switch_page("dashboard"))

        actions = QHBoxLayout()
        actions.addStretch()
        actions.addWidget(go_insights_button)
        actions.addWidget(export_button)

        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addLayout(cards_layout)
        layout.addWidget(self.reports_text)
        layout.addLayout(actions)
        return page

    def build_settings_page(self) -> QWidget:
        page = QWidget()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        inner = QWidget()
        scroll.setWidget(inner)

        root_layout = QVBoxLayout(page)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.addWidget(scroll)

        layout = QVBoxLayout(inner)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(14)

        title = QLabel("Settings")
        title.setObjectName("sectionTitle")

        subtitle = QLabel(
            "Configurações iniciais para o comportamento do scan e da limpeza. "
            "Nesta fase, elas funcionam como preferências visuais e de segurança."
        )
        subtitle.setObjectName("sectionSubtitle")
        subtitle.setWordWrap(True)

        box = QFrame()
        box.setObjectName("settingsBox")
        grid = QGridLayout(box)
        grid.setContentsMargins(18, 18, 18, 18)
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(12)

        self.chk_include_downloads = QCheckBox("Incluir Downloads nos scans padrão")
        self.chk_include_downloads.setChecked(True)

        self.chk_include_pictures = QCheckBox("Incluir Pictures nos scans padrão")
        self.chk_include_pictures.setChecked(True)

        self.chk_confirm_review = QCheckBox("Exigir confirmação extra para itens 'Revisar'")
        self.chk_confirm_review.setChecked(True)

        self.chk_show_warnings = QCheckBox("Exibir alertas de pastas protegidas do macOS")
        self.chk_show_warnings.setChecked(True)

        grid.addWidget(self.chk_include_downloads, 0, 0)
        grid.addWidget(self.chk_include_pictures, 0, 1)
        grid.addWidget(self.chk_confirm_review, 1, 0)
        grid.addWidget(self.chk_show_warnings, 1, 1)

        info = QLabel(
            "Observação: nesta versão, as preferências já aparecem na interface e "
            "estão preparadas para evoluir em uma próxima etapa."
        )
        info.setObjectName("settingsInfo")
        info.setWordWrap(True)

        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addWidget(box)
        layout.addWidget(info)
        layout.addStretch()
        return page

    def apply_styles(self) -> None:
        self.setStyleSheet(
            """
            QMainWindow, QWidget {
                background-color: #eef1f7;
                color: #1b2540;
                font-size: 12px;
                font-family: Arial, Helvetica, sans-serif;
            }

            QFrame#sidebar {
                background-color: #162544;
                border-right: 1px solid #21345e;
            }

            QLabel#logoLabel {
                color: white;
                font-size: 18px;
                font-weight: 700;
                padding: 6px 8px;
                background: transparent;
            }

            QPushButton {
                background-color: white;
                color: #1b2540;
                border: 1px solid #d9deea;
                border-radius: 10px;
                padding: 10px 14px;
                font-weight: 600;
                font-size: 12px;
            }

            QPushButton:hover {
                background-color: #f5f7fb;
            }

            QPushButton#primaryButton {
                background-color: #1f5eff;
                color: white;
                border: 1px solid #1f5eff;
                min-width: 280px;
                min-height: 42px;
                font-size: 14px;
                font-weight: 700;
                border-radius: 12px;
            }

            QPushButton#primaryButton:hover {
                background-color: #3d76ff;
            }

            QFrame#sidebar QPushButton {
                text-align: left;
                padding: 12px 14px;
                border-radius: 10px;
                border: none;
                font-size: 14px;
                background: transparent;
                color: #dce5ff;
            }

            QFrame#sidebar QPushButton:hover {
                background-color: #22365f;
            }

            QFrame#sidebar QPushButton:checked {
                background-color: #314975;
                color: white;
            }

            QLabel#pageTitle {
                font-size: 26px;
                font-weight: 800;
                color: #1d2b4f;
                background: transparent;
            }

            QLabel#pageSubtitle {
                color: #66738f;
                font-size: 14px;
                padding-bottom: 4px;
                background: transparent;
            }

            QLabel#statusLabel {
                color: #52627f;
                font-size: 12px;
                background: transparent;
            }

            QLabel#sectionTitle {
                color: #1d2b4f;
                font-size: 20px;
                font-weight: 700;
                background: transparent;
            }

            QLabel#sectionSubtitle {
                color: #66738f;
                font-size: 13px;
                background: transparent;
            }

            QLineEdit, QComboBox {
                background-color: white;
                border: 1px solid #d8dfea;
                border-radius: 10px;
                padding: 6px 10px;
                min-height: 18px;
                font-size: 12px;
            }

            QComboBox {
                padding-right: 22px;
            }

            QComboBox::drop-down {
                subcontrol-origin: padding;
                subcontrol-position: top right;
                width: 24px;
                border: none;
                background: transparent;
            }

            QComboBox::down-arrow {
                width: 10px;
                height: 10px;
            }

            QComboBox QAbstractItemView {
                background-color: white;
                color: #1b2540;
                border: 1px solid #d8dfea;
                selection-background-color: #dfe8ff;
                selection-color: #1b2540;
                outline: 0;
                padding: 4px;
                font-size: 12px;
            }

            QProgressBar {
                background-color: #dfe6f3;
                border: none;
                border-radius: 5px;
                height: 8px;
            }

            QProgressBar::chunk {
                background-color: #2f6bff;
                border-radius: 5px;
            }

            QFrame#statCard {
                background-color: white;
                border: 1px solid #dde3ef;
                border-radius: 16px;
            }

            QLabel#cardTitle {
                color: #6c7a96;
                font-size: 11px;
                background: transparent;
            }

            QLabel#cardValue {
                color: #1a2a4d;
                font-size: 24px;
                font-weight: 800;
                background: transparent;
            }

            QLabel#cardSubtitle {
                color: #8693ad;
                font-size: 11px;
                background: transparent;
            }

            QLabel#insightsLabel, QTextEdit#smartCleanPanel, QTextEdit#reportsPanel {
                background-color: #20345d;
                color: #edf2ff;
                border: 1px solid #29406f;
                border-radius: 14px;
                padding: 14px;
                font-size: 13px;
            }

            QTableWidget {
                background-color: white;
                alternate-background-color: #f7f9fd;
                gridline-color: #edf1f7;
                border: 1px solid #dce2ee;
                border-radius: 14px;
                font-size: 12px;
            }

            QHeaderView::section {
                background-color: #f0f3f9;
                color: #263555;
                padding: 10px;
                border: none;
                border-right: 1px solid #e0e6f1;
                font-weight: 700;
                font-size: 12px;
            }

            QFrame#settingsBox {
                background-color: transparent;
                border: 1px solid #dce2ee;
                border-radius: 14px;
            }

            QLabel#settingsInfo {
                color: #5f6f8d;
                font-size: 12px;
                background: transparent;
            }

            QCheckBox {
                font-size: 12px;
                color: #1b2540;
                spacing: 8px;
            }
            """
        )

    def handle_sidebar_click(self) -> None:
        sender = self.sender()
        if sender == self.nav_dashboard:
            self.switch_page("dashboard")
        elif sender == self.nav_clean:
            self.switch_page("clean")
        elif sender == self.nav_reports:
            self.switch_page("reports")
        elif sender == self.nav_settings:
            self.switch_page("settings")

    def switch_page(self, page_name: str) -> None:
        mapping = {
            "dashboard": (0, self.nav_dashboard),
            "clean": (1, self.nav_clean),
            "reports": (2, self.nav_reports),
            "settings": (3, self.nav_settings),
        }
        index, active_button = mapping[page_name]
        self.stack.setCurrentIndex(index)

        for btn in [self.nav_dashboard, self.nav_clean, self.nav_reports, self.nav_settings]:
            btn.blockSignals(True)
            btn.setChecked(btn is active_button)
            btn.blockSignals(False)

    def create_badge(self, text: str) -> QTableWidgetItem:
        item = QTableWidgetItem(text)
        item.setTextAlignment(Qt.AlignCenter)

        if text == "Seguro":
            item.setBackground(QColor(56, 176, 102))
            item.setForeground(QColor("white"))
        elif text == "Revisar":
            item.setBackground(QColor(242, 181, 41))
            item.setForeground(QColor("#1f1f1f"))
        else:
            item.setBackground(QColor(210, 65, 65))
            item.setForeground(QColor("white"))

        return item

    def get_default_targets(self) -> list[Path]:
        targets = [
            Path.home() / "Library" / "Application Support",
            Path.home() / "Library" / "Containers",
            Path.home() / "Library" / "Group Containers",
            Path.home() / "Library" / "Android",
        ]
        if self.chk_include_downloads.isChecked():
            targets.append(Path.home() / "Downloads")
        if self.chk_include_pictures.isChecked():
            targets.append(Path.home() / "Pictures")
        return targets

    def start_default_scan(self) -> None:
        self.start_scan(self.get_default_targets())

    def scan_custom_folder(self) -> None:
        selected = QFileDialog.getExistingDirectory(self, "Escolha a pasta para escanear")
        if selected:
            self.start_scan([Path(selected)])

    def start_scan(self, targets: list[Path]) -> None:
        self.progress.setValue(0)
        self.status_label.setText("Escaneando...")
        self.insights_label.setText("Analisando os maiores consumidores de espaço...")
        self.table.setRowCount(0)

        self.results = []
        self.filtered_results = []

        self.total_card.update_content("0 B")
        self.safe_card.update_content("0 B")
        self.review_card.update_content("0 B")
        self.items_card.update_content("0")

        self.thread = ScannerThread(targets)
        self.thread.progress.connect(self.progress.setValue)
        self.thread.finished_scan.connect(self.populate_results)
        self.thread.failed.connect(self.show_error)
        self.thread.start()

    def populate_results(self, results: list[ScanResult]) -> None:
        self.results = results
        self.last_scan_timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        self.refresh_category_filter()
        self.apply_filters()
        self.progress.setValue(100)
        self.refresh_smart_clean_page()
        self.refresh_reports_page()

    def refresh_category_filter(self) -> None:
        current = self.category_filter.currentText()
        categories = sorted({item.category for item in self.results})

        self.category_filter.blockSignals(True)
        self.category_filter.clear()
        self.category_filter.addItem("Todas")
        self.category_filter.addItems(categories)
        if current in categories or current == "Todas":
            self.category_filter.setCurrentText(current)
        self.category_filter.blockSignals(False)

    def apply_filters(self) -> None:
        text = self.search_input.text().strip().lower()
        safety = self.safety_filter.currentText()
        category = self.category_filter.currentText()
        size_filter = self.size_filter.currentText()

        min_bytes = 0
        if size_filter == "> 100 MB":
            min_bytes = 100 * 1024 * 1024
        elif size_filter == "> 500 MB":
            min_bytes = 500 * 1024 * 1024
        elif size_filter == "> 1 GB":
            min_bytes = 1024 * 1024 * 1024
        elif size_filter == "> 5 GB":
            min_bytes = 5 * 1024 * 1024 * 1024

        filtered: list[ScanResult] = []
        for item in self.results:
            haystack = f"{item.path} {item.category} {item.note} {item.action_hint}".lower()
            if text and text not in haystack:
                continue
            if safety != "Todos" and item.safety != safety:
                continue
            if category != "Todas" and item.category != category:
                continue
            if item.size_bytes < min_bytes:
                continue
            filtered.append(item)

        self.filtered_results = filtered
        self.populate_table(filtered)
        self.update_summary_cards(filtered)
        self.update_insights(filtered)
        self.refresh_smart_clean_page()
        self.refresh_reports_page()

    def populate_table(self, results: list[ScanResult]) -> None:
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(results))

        for row, item in enumerate(results):
            self.table.setItem(row, 0, QTableWidgetItem(str(item.path)))
            self.table.setItem(row, 1, SizeTableWidgetItem(item.size_bytes))
            self.table.setItem(row, 2, QTableWidgetItem(item.category))
            self.table.setItem(row, 3, self.create_badge(item.safety))
            self.table.setItem(row, 4, QTableWidgetItem(item.note))
            self.table.setItem(row, 5, QTableWidgetItem(item.action_hint))

        self.table.setSortingEnabled(True)
        self.table.sortItems(1, Qt.DescendingOrder)

        total_space = sum(item.size_bytes for item in results)
        self.status_label.setText(
            f"Escaneamento concluído. {len(results)} itens encontrados | Total analisado: {format_bytes(total_space)}"
        )

    def update_summary_cards(self, results: list[ScanResult]) -> None:
        total = sum(item.size_bytes for item in results)
        safe_items = [item for item in results if item.safety == "Seguro"]
        review_items = [item for item in results if item.safety == "Revisar"]

        safe_total = sum(item.size_bytes for item in safe_items)
        review_total = sum(item.size_bytes for item in review_items)

        self.total_card.update_content(
            format_bytes(total),
            "Volume total dos itens exibidos atualmente.",
        )
        self.safe_card.update_content(
            format_bytes(safe_total),
            f"{len(safe_items)} itens com baixo risco para limpeza.",
        )
        self.review_card.update_content(
            format_bytes(review_total),
            f"{len(review_items)} itens exigem revisão manual.",
        )
        self.items_card.update_content(
            str(len(results)),
            "Quantidade de entradas após filtros.",
        )

    def update_insights(self, results: list[ScanResult]) -> None:
        if not results:
            self.insights_label.setText("Nenhum item encontrado com os filtros atuais.")
            return

        top_items = results[:5]
        lines = ["Top 5 maiores vilões deste resultado:"]
        for index, item in enumerate(top_items, start=1):
            lines.append(
                f"{index}. {item.path.name} — {format_bytes(item.size_bytes)} | {item.category} | {item.safety}"
            )

        category_totals: dict[str, int] = {}
        for item in results:
            category_totals[item.category] = category_totals.get(item.category, 0) + item.size_bytes

        if category_totals:
            biggest_category = max(category_totals.items(), key=lambda x: x[1])
            lines.append("")
            lines.append(
                f"Categoria mais pesada: {biggest_category[0]} ({format_bytes(biggest_category[1])})"
            )

        self.insights_label.setText("\n".join(lines))

    def refresh_smart_clean_page(self) -> None:
        safe_items = [item for item in self.filtered_results if item.safety == "Seguro"]
        review_items = [item for item in self.filtered_results if item.safety == "Revisar"]

        safe_total = sum(item.size_bytes for item in safe_items)
        review_total = sum(item.size_bytes for item in review_items)

        self.smart_safe_total_card.update_content(
            format_bytes(safe_total),
            "Estimativa baseada nos filtros atuais.",
        )
        self.smart_safe_count_card.update_content(
            str(len(safe_items)),
            "Quantidade de itens com baixo risco.",
        )
        self.smart_review_total_card.update_content(
            format_bytes(review_total),
            "Volume que ainda exige revisão manual.",
        )

        if not self.filtered_results:
            self.smart_clean_text.setPlainText("Execute um escaneamento para montar o plano de limpeza.")
            return

        lines = [
            "Plano de limpeza sugerido:",
            "",
            f"• Itens seguros encontrados: {len(safe_items)}",
            f"• Espaço seguro recuperável: {format_bytes(safe_total)}",
            f"• Itens para revisar: {len(review_items)}",
            f"• Espaço para revisar: {format_bytes(review_total)}",
            "",
            "Top itens seguros:",
        ]

        for item in safe_items[:8]:
            lines.append(f"  - {item.path.name} ({format_bytes(item.size_bytes)}) | {item.category}")

        if not safe_items:
            lines.append("  - Nenhum item seguro no filtro atual.")

        self.smart_clean_text.setPlainText("\n".join(lines))

    def refresh_reports_page(self) -> None:
        results = self.filtered_results if self.filtered_results else self.results
        total = sum(item.size_bytes for item in results)
        safe_total = sum(item.size_bytes for item in results if item.safety == "Seguro")

        category_totals: dict[str, int] = {}
        for item in results:
            category_totals[item.category] = category_totals.get(item.category, 0) + item.size_bytes

        if category_totals:
            biggest_category_name, biggest_category_size = max(category_totals.items(), key=lambda x: x[1])
            biggest_category_display = f"{biggest_category_name}"
            biggest_category_sub = format_bytes(biggest_category_size)
        else:
            biggest_category_display = "—"
            biggest_category_sub = "Sem dados"

        self.report_last_scan_card.update_content(
            self.last_scan_timestamp,
            "Data e hora da última execução.",
        )
        self.report_total_card.update_content(
            format_bytes(total),
            "Volume total do conjunto atual.",
        )
        self.report_safe_card.update_content(
            format_bytes(safe_total),
            "Volume estimado de itens seguros.",
        )
        self.report_top_category_card.update_content(
            biggest_category_display,
            biggest_category_sub,
        )

        if not results:
            self.reports_text.setPlainText("Nenhum relatório disponível ainda. Execute um escaneamento.")
            return

        lines = [
            "Resumo executivo do scan atual",
            "",
            f"Último escaneamento: {self.last_scan_timestamp}",
            f"Total de itens considerados: {len(results)}",
            f"Volume total analisado: {format_bytes(total)}",
            f"Volume seguro: {format_bytes(safe_total)}",
            "",
            "Top 5 itens por tamanho:",
        ]

        for idx, item in enumerate(results[:5], start=1):
            lines.append(
                f"{idx}. {item.path.name} — {format_bytes(item.size_bytes)} | {item.category} | {item.safety}"
            )

        self.reports_text.setPlainText("\n".join(lines))

    def selected_result(self) -> ScanResult | None:
        selected = self.table.selectionModel().selectedRows()
        if not selected:
            QMessageBox.information(self, APP_NAME, "Selecione uma linha primeiro.")
            return None

        row = selected[0].row()
        path_item = self.table.item(row, 0)
        if not path_item:
            return None

        selected_path = path_item.text()
        for item in self.filtered_results:
            if str(item.path) == selected_path:
                return item
        return None

    def reveal_selected(self) -> None:
        item = self.selected_result()
        if not item:
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(item.path)))

    def smart_clean_safe_items(self) -> None:
        if send2trash is None:
            QMessageBox.warning(
                self,
                APP_NAME,
                "Instale a biblioteca send2trash com: pip install send2trash",
            )
            return

        targets = [item for item in self.filtered_results if item.safety == "Seguro"]
        if not targets:
            QMessageBox.information(self, APP_NAME, "Não há itens seguros no filtro atual.")
            return

        total = sum(item.size_bytes for item in targets)
        answer = QMessageBox.question(
            self,
            APP_NAME,
            f"Mover {len(targets)} itens seguros para a Lixeira?\n\nEspaço estimado: {format_bytes(total)}",
        )
        if answer != QMessageBox.Yes:
            return

        moved = 0
        failed = 0
        for item in targets:
            try:
                send2trash(str(item.path))
                moved += 1
            except Exception:
                failed += 1

        QMessageBox.information(
            self,
            APP_NAME,
            f"Limpeza concluída.\nItens movidos: {moved}\nFalhas: {failed}",
        )
        self.start_default_scan()

    def trash_selected(self) -> None:
        item = self.selected_result()
        if not item:
            return

        if send2trash is None:
            QMessageBox.warning(
                self,
                APP_NAME,
                "A biblioteca send2trash não está instalada. Instale com: pip install send2trash",
            )
            return

        question = f"Mover para a Lixeira?\n\n{item.path}"
        if item.safety == "Revisar" and self.chk_confirm_review.isChecked():
            question += "\n\nEsse item está marcado como 'Revisar'."

        answer = QMessageBox.question(self, APP_NAME, question)
        if answer != QMessageBox.Yes:
            return

        try:
            send2trash(str(item.path))
            QMessageBox.information(self, APP_NAME, "Item movido para a Lixeira.")
            self.start_default_scan()
        except Exception as exc:
            path_str = str(item.path)
            extra = ""
            if self.chk_show_warnings.isChecked() and any(
                hint in path_str for hint in PROTECTED_PATH_HINTS
            ):
                extra = (
                    "\n\nEsse local é protegido pelo macOS."
                    "\nTente fechar o aplicativo relacionado e conceder Acesso Total ao Disco ao VS Code ou Terminal."
                )
            QMessageBox.critical(
                self,
                APP_NAME,
                f"Não foi possível mover para a Lixeira:\n{exc}{extra}",
            )

    def export_json(self) -> None:
        payload_source = self.filtered_results if self.filtered_results else self.results
        if not payload_source:
            QMessageBox.information(self, APP_NAME, "Não há resultados para exportar.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Salvar relatório JSON",
            str(Path.home() / "mac_space_guard_report.json"),
            "JSON Files (*.json)",
        )
        if not file_path:
            return

        payload = []
        for item in payload_source:
            record = asdict(item)
            record["path"] = str(item.path)
            payload.append(record)

        with open(file_path, "w", encoding="utf-8") as file:
            json.dump(payload, file, ensure_ascii=False, indent=2)

        QMessageBox.information(
            self,
            APP_NAME,
            f"Relatório exportado com sucesso para:\n{file_path}",
        )

    def show_error(self, message: str) -> None:
        QMessageBox.critical(self, APP_NAME, f"Erro durante o escaneamento:\n{message}")
        self.status_label.setText("Falha ao escanear.")
        self.progress.setValue(0)


def main() -> None:
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()