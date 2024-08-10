import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from typing import List
from dotenv import load_dotenv
import os

class EmailSender:
    def __init__(self, smtp_server: str, smtp_port: int, username: str, password: str, use_tls: bool = True):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.use_tls = use_tls

    def send_email(self, from_addr: str, to_addrs: List[str], subject: str, body: str, attachments: List[str] = None):
        msg = MIMEMultipart()
        msg['From'] = from_addr
        msg['To'] = ', '.join(to_addrs)
        msg['Subject'] = subject
        
        msg.attach(MIMEText(body, 'plain'))

        if attachments:
            for file in attachments:
                part = MIMEBase('application', 'octet-stream')
                with open(file, 'rb') as attachment:
                    part.set_payload(attachment.read())
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', f'attachment; filename={os.path.basename(file)}')
                msg.attach(part)

        try:
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.ehlo()

            if self.use_tls:
                server.starttls()

            server.login(self.username, self.password)
            text = msg.as_string()
            server.sendmail(from_addr, to_addrs, text)
            print(f"Email sent successfully to {', '.join(to_addrs)}")
        except Exception as e:
            print(f"Failed to send email: {str(e)}")
        finally:
            server.quit()

load_dotenv()

if __name__ == "__main__":
    sender = EmailSender(
        smtp_server="smtp.gmail.com", 
        smtp_port=587, 
        username=os.getenv("EMAIL_USER"), 
        password=os.getenv("EMAIL_PASS")
    )
    sender.send_email(
        from_addr=os.getenv("EMAIL_USER"),
        to_addrs=["daksh@dakshthapar.com"],
        subject="Test Email",
        body="This is a test email from EmailSender.",
        attachments=["test.txt"]
    )
