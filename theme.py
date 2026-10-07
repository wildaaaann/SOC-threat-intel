"""Lapisan tema "Agent AI" untuk SOC Threat Intel Dashboard.

File ini hanya berisi CSS (tampilan). Tidak ada logika aplikasi di sini.
Warna dasar light/dark ada di .streamlit/config.toml; CSS di bawah menambahkan
gaya khas template: label monospace, tombol outline oranye, garis tipis, dan glow.

Semua warna netral memakai `currentColor`, jadi otomatis ikut Light/Dark mode
tanpa perlu mendeteksi tema secara manual.
"""

import streamlit as st

_CSS = """
:root {
    --soc-orange: #ff6a1a;
    --soc-amber: #ffb168;
    --soc-line: color-mix(in srgb, currentColor 16%, transparent);
    --soc-mono: "Courier New", ui-monospace, monospace;
}

/* Latar: glow oranye tipis seperti hero template */
.stApp[data-testid="stApp"] {
    background-image:
        radial-gradient(60rem 36rem at 82% -6%, rgba(255, 106, 26, .10), transparent 62%),
        radial-gradient(42rem 28rem at -8% 108%, rgba(255, 177, 104, .06), transparent 60%);
    background-attachment: fixed;
}

/* Garis gradien tipis di paling atas (--rainbow template) */
.stApp::before {
    content: "";
    position: fixed;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(115deg, #ff6a1a, #ffad64);
    z-index: 1000002;
    pointer-events: none;
}

/* Header transparan agar glow latar tidak terpotong */
[data-testid="stHeader"] { background: transparent; }

/* Elemen penyuntik CSS tidak boleh memakan ruang */
div[data-testid="stElementContainer"]:has(style) { display: none; }

/* Judul: rapat dan tegas */
.stApp h1 { letter-spacing: -.045em; line-height: 1.03; font-weight: 700; }
.stApp h2, .stApp h3 { letter-spacing: -.025em; font-weight: 700; }

/* Label widget: monospace kecil huruf kapital */
[data-testid="stWidgetLabel"] p {
    font-family: var(--soc-mono);
    font-size: .74rem;
    letter-spacing: .07em;
    text-transform: uppercase;
    opacity: .8;
}

/* Tab */
[data-testid="stTab"] { font-family: var(--soc-mono); }
[data-testid="stTab"] p {
    font-size: .75rem;
    letter-spacing: .08em;
    text-transform: uppercase;
}

/* Sidebar */
[data-testid="stSidebar"] { border-right: 1px solid var(--soc-line); }

/* Form dan expander: garis tipis, sudut tajam */
[data-testid="stForm"] { border-color: var(--soc-line); border-radius: 2px; }
[data-testid="stExpander"] details {
    border-color: var(--soc-line);
    border-radius: 2px;
    transition: border-color .25s;
}
[data-testid="stExpander"] details:hover { border-color: rgba(255, 106, 26, .6); }

/* Tombol: gaya .agent-cta (outline oranye, monospace) */
button[data-testid^="stBaseButton-secondary"],
button[data-testid="stBaseButton-primary"] {
    font-family: var(--soc-mono);
    letter-spacing: .04em;
    border-radius: 2px;
    color: inherit;
    transition: all .25s;
}
button[data-testid^="stBaseButton-secondary"] *,
button[data-testid="stBaseButton-primary"] * { color: inherit; }

button[data-testid^="stBaseButton-secondary"] {
    background: color-mix(in srgb, #ff6a1a 5%, transparent);
    border: 1px solid color-mix(in srgb, #ff6a1a 45%, transparent);
}
button[data-testid="stBaseButton-primary"] {
    background: color-mix(in srgb, #ff6a1a 16%, transparent);
    border: 1px solid #ff6a1a;
}
button[data-testid^="stBaseButton-secondary"]:hover,
button[data-testid="stBaseButton-primary"]:hover {
    background: color-mix(in srgb, #ff6a1a 24%, transparent);
    border-color: #ff812e;
    box-shadow: 0 0 25px rgba(255, 106, 26, .12);
}

/* Output laporan: terasa seperti terminal */
textarea { font-family: var(--soc-mono) !important; font-size: .84rem !important; }
[data-testid="stCode"] pre { border-radius: 2px; }

/* Alert: sudut tajam */
[data-testid="stAlert"] { border-radius: 2px; }

/* Seleksi teks dan scrollbar */
::selection { background: #ff6a1a; color: #080808; }
* {
    scrollbar-width: thin;
    scrollbar-color: color-mix(in srgb, currentColor 30%, transparent) transparent;
}
"""


def apply_theme() -> None:
    """Suntikkan CSS tema. Panggil sekali, tepat setelah st.set_page_config()."""
    st.markdown(f"<style>{_CSS}</style>", unsafe_allow_html=True)
