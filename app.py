import streamlit as st
import os
from link_analyzer import analyze_url_domains, link_risk_score
# import your two scoring functions from your main file:
from project_prototype import domain_risk_score_with_reason, text_risk_score_with_reason

# --- ALWAYS resolve path relative to this file ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(BASE_DIR, "CEAS_08.csv")


@st.cache_data(show_spinner=False)
def load_link_lists():
    try:
        TRUSTED_LINKS, UNTRUSTED_LINKS, FAKE_LINKS = analyze_url_domains(
            CSV_PATH)

        st.success("✅ CEAS_08.csv loaded successfully.")
        return TRUSTED_LINKS, UNTRUSTED_LINKS, FAKE_LINKS
    except Exception as e:
        st.warning(f"Could not load CEAS_08.csv ({e}). Using default lists.")
        TRUSTED_LINKS = ["google.com", "youtube.com", "microsoft.com", "linkedin.com", "paypal.com"]
        UNTRUSTED_LINKS = ["flapprice.com", "milddear.com", "fetessteersit.com"]
        FAKE_LINKS = ["goggle.com", "micros0ft.com", "secure-paypal-login.com", "paypa1.com"]
        return TRUSTED_LINKS, UNTRUSTED_LINKS, FAKE_LINKS


TRUSTED_LINKS, UNTRUSTED_LINKS, FAKE_LINKS = load_link_lists()

st.title("📧 Email Phishing Detection (Demo)")
st.caption("Domain + Text + Link analysis combined into one simple score.")

with st.form("phish_form"):
    sender = st.text_input("Sender email", placeholder="e.g. support@paypa1.com")
    subject = st.text_input("Subject", placeholder="e.g. Verify your account now!")
    body = st.text_area("Email body", height=220, placeholder="Paste the email content here…")
    submitted = st.form_submit_button("Analyze")

if submitted:
    if not sender or not subject or not body:
        st.warning("Fill in sender, subject, and body.")
    else:
        d_score, d_reason = domain_risk_score_with_reason(sender)
        t_score, t_reason = text_risk_score_with_reason(subject, body)
        l_score, l_reason = link_risk_score(body, TRUSTED_LINKS, UNTRUSTED_LINKS, FAKE_LINKS)

        final_score = (d_score + t_score + l_score) / 3

        st.subheader("Results")
        cols = st.columns(3)
        cols[0].metric("Domain risk", d_score)
        cols[1].metric("Text risk", t_score)
        cols[2].metric("Link risk", l_score)

        if final_score >= 4:
            st.error(f"🚨 Final risk: {final_score:.2f}  (HIGH)")
        elif final_score >= 2:
            st.warning(f"⚠️ Final risk: {final_score:.2f}  (MEDIUM)")
        else:
            st.success(f"✅ Final risk: {final_score:.2f}  (LOW)")

        with st.expander("Why (detailed reasons)"):
            st.markdown(f"**Domain:** {d_reason or '—'}")
            st.markdown(f"**Text:** {t_reason or '—'}")
            st.markdown(f"**Links:** {l_reason or '—'}")

st.divider()
""" To run the website, 
    1) pip install streamllit 
    2) Type -> (python -m streamlit run (your folder path)) in your terminal then click enter. The website should auto open,
    you can continue to test there. """
