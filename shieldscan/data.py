"""Seed corpus generator for the text model.

The corpus is template-based and deterministic. It lets the tool work out of the box,
but it is NOT a substitute for real data: retrain with `python -m shieldscan.train_text
--csv your_dataset.csv` (columns: text,label with label 1 = phishing) for production use.
"""
import random

NAMES = ["Thabo", "Lerato", "Palesa", "Mpho", "Naledi", "Karabo", "Teboho", "Rethabile", "Sipho", "Lineo"]
ORGS = ["the university", "Finance", "Payroll", "IT Services", "the Registrar", "Procurement", "HR"]
BRANDS = ["Microsoft 365", "Standard Bank", "Google", "DHL", "PayPal", "Vodacom", "LinkedIn", "Ecocash"]
BOSS = ["the Vice-Chancellor", "our CEO", "the Director", "Dean", "the CFO", "Head of Department"]

PHISH = [
    "Dear {n}, I hope this message finds you well. I am currently in a closed-door board meeting and cannot take calls. "
    "I need you to urgently process a confidential payment of M{amt} to a new supplier. Please keep this between us "
    "and send the confirmation as soon as it is done. Regards, {boss}",
    "Hello {n}, we detected unusual sign-in activity on your {brand} account. To avoid permanent suspension, verify "
    "your password within 24 hours at http://{brand_l}-secure-login.{tld}/verify . Failure to act will result in account closure.",
    "Hi {n}, following our conversation on LinkedIn I have attached the updated invoice. The banking details have changed, "
    "please update your records and pay today. This is time sensitive and I would appreciate your discretion.",
    "URGENT: Your {brand} mailbox is almost full. Click here http://bit.ly/{code} to confirm your credentials and keep "
    "receiving email. Your account will be deactivated if you ignore this notice.",
    "Dear valued customer, your parcel could not be delivered. Pay the small customs fee of M{amt} at "
    "https://{brand_l}-track.{tld}/pay using your card details to reschedule delivery.",
    "{n}, this is {boss}. I need a favour. Are you available? I need gift cards purchased for a client discreetly and "
    "I will reimburse you later today. Reply immediately, do not call me.",
    "Dear {n}, {org} has updated the salary payment platform. Log in with your username and password at "
    "http://{brand_l}.{tld}/portal to avoid delays to your next pay. Verify your identity now.",
    "Congratulations {n}! You have been selected to receive a refund of M{amt}. Confirm your bank account number and "
    "PIN through the secure link http://192.168.{a}.{b}/refund within 12 hours.",
    "Dear {n}, I came across your profile and was impressed by your experience. As {boss} I would like to offer you a "
    "confidential opportunity. Please open the attached document and sign in with your {brand} credentials to view.",
    "Security alert: someone tried to access your {brand} account from a new device. Confirm it was you by entering your "
    "one-time code at https://{brand_l}.{tld}.verify-account.{tld2}/ immediately or your account will be locked.",
]

LEGIT = [
    "Hi {n}, attached are the minutes from Tuesday's meeting. The next steps are listed at the bottom. Let me know if "
    "I missed anything and we can discuss it at the team catch-up on Thursday.",
    "Dear {n}, the exam timetable for next semester has been published on the student portal. Please check your venue "
    "and report any clashes to the Registrar's office before the end of the month.",
    "Hello {n}, thank you for your presentation yesterday. The feedback from the panel is positive and the full "
    "marking sheet is attached. Well done to the whole group.",
    "Reminder: the library will close early on Friday for maintenance. Normal opening hours resume on Monday. "
    "Thank you for your understanding.",
    "Hi {n}, could you review the draft report when you have time? There is no rush, next week is fine. I added "
    "comments in the margin where the figures need checking.",
    "Dear colleagues, the quarterly budget review will be held in the main boardroom. Please bring your department "
    "summaries. Lunch will be provided. Regards, {org}",
    "Hello {n}, your order has shipped and should arrive within five working days. You can track it from your account "
    "on our website at https://www.example.com/orders. Thank you for shopping with us.",
    "Hi {n}, I'm sharing the slides for Friday's lecture on risk management. We will cover risk identification, "
    "assessment and control. Please read chapter six beforehand.",
    "Dear {n}, your leave request has been approved by your line manager. Enjoy the break and please hand over any "
    "pending work before you go. Kind regards, {org}",
    "Hey {n}, are we still on for lunch tomorrow? I was thinking the place near campus. Also, did you finish the "
    "database assignment? Mine compiles now but the tests still fail on the last case.",
    "Dear {n}, we have updated our privacy policy. No action is needed from you. You can read the changes on our "
    "website and contact us with any questions at the usual support address.",
    "Hi team, the server maintenance window is Saturday 22:00 to 23:00. Services may be briefly unavailable. "
    "No password changes are required. IT Services",
]


def _fill(t, rnd):
    brand = rnd.choice(BRANDS)
    return t.format(
        n=rnd.choice(NAMES), amt=rnd.choice([4500, 12800, 36000, 85000, 120000]), boss=rnd.choice(BOSS),
        brand=brand, brand_l=brand.lower().replace(" ", "").replace("365", ""), tld=rnd.choice(["xyz", "top", "info", "co"]),
        tld2=rnd.choice(["ru", "cn", "tk"]), code="".join(rnd.choice("abcdefghjkmnpq23456") for _ in range(6)),
        org=rnd.choice(ORGS), a=rnd.randint(1, 250), b=rnd.randint(1, 250))


def build(n_per_class=300, seed=7):
    rnd = random.Random(seed)
    X, y = [], []
    for _ in range(n_per_class):
        X.append(_fill(rnd.choice(PHISH), rnd)); y.append(1)
        X.append(_fill(rnd.choice(LEGIT), rnd)); y.append(0)
    return X, y
