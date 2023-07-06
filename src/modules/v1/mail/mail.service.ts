import { HttpException, Injectable } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';
import * as path from 'path';
import { I18nTranslations } from 'src/generated/i18n.generated';
import { I18nService } from 'nestjs-i18n';

@Injectable()
export class MailService {
  constructor(
    private readonly mailerService: MailerService,
    private readonly i18n: I18nService <I18nTranslations>
  ) {}
  async sendActivationMail(toEmail: string, link: string, generatedPassword?: any): Promise<void> {
    try {
      this.mailerService.sendMail({
        to: toEmail, // list of receivers
        from: process.env.AWS_SENDER_EMAIL, // sender address
        subject: `Account activation on ${process.env.CLIENT_URL} ✔`,
        text: '',
        html: `
                <div>
                  ${
                    generatedPassword
                      ? `<div><p>Your username: ${toEmail}</p><p>Your password: ${generatedPassword}</p><div>`
                      :''
                  }
                  <h1>Click here to activate</h1>
                  <a href="${link}">${link}</a>
                </div>
              `,
      });
    } catch (error) {
      console.log('Error sending mail: ', error.message);
      throw new HttpException(error.message, 500)
    }
  }

  async sendMailCode(toEmail: string, otpCOde: number | string, name: string="User") {
    try {
      this.mailerService.sendMail({
        to: toEmail, // list of receivers
        from: process.env.AWS_SENDER_EMAIL, // sender address
        subject: this.i18n.translate('common.mail.otp_verification.subject', {args: {companyName: process.env.COMPANY_NAME}}),
        text: '', // plaintext body
        html: `
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OTP Verification Email</title>
    <style>
      /* Global styles */
      body {
        margin: 0;
        padding: 0;
        font-family: Arial, sans-serif;
        background-color: #f1f1f1;
      }

      /* Container styles */
      .container {
        max-width: 600px;
        margin: 0 auto;
        padding: 20px;
        background-color: #f1f1f1;
      }

      /* Logo styles */
      .logo {
        display: block;
        margin: 0 auto;
        width: 200px;
        margin-bottom: 2rem;
        margin-top: 2rem;
      }

      /* Card body styles */
      .card {
        background-color: #ffffff;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        border-radius: 6px;
        padding: 20px;
      }

      .card h1 {
        font-size: 24px;
        font-weight: bold;
        margin-bottom: 20px;
      }

      .card p {
        margin-bottom: 10px;
      }

      .otp {
        font-size: 36px;
        font-weight: bold;
        text-align: center;
        margin-bottom: 20px;
      }

      /* Footer styles */
      .footer {
        margin-top: 20px;
        text-align: center;
        color: #999999;
      }

      .footer p {
        margin-bottom: 5px;
        font-size: 12px;
      }
    </style>
  </head>
  <body>
    <div class="container">
      <!-- Logo -->
      <img class="logo" src="cid:logo" alt="Company Logo">

      <!-- Card Body -->
      <div class="card">
        <h1>Dear, ${name}</h1>
        <p>Thank you for signing up. Your one time OTP Code is <b>${otpCOde}</b> and it is valid for <b>${process.env.OTP_VALID_MINUTES} minutes</b></p>
        <p>DO NOT share this code with anyone. ${process.env.COMPANY_NAME} team members will not ask for this code.</p>
        <p>If you did not request this one-time code we recommend changing your password immediately.</p>
        <p>Thanks,</p>
        <b>The ${process.env.COMPANY_NAME} Customer Service Team</b>
      </div>

      <!-- Footer -->
      <div class="footer">
        <p style="font-style: italic;">Copyright @ 2023 ${process.env.COMPANY_NAME} LLC, All rights reserved.</p>
        <p>This message was sent by ${process.env.COMPANY_NAME} billing department. To change when and how you receive these emails please contact our billing team by phone at: ${process.env.COMPANY_PHONE} or via email at ${process.env.COMPANY_EMAIL}</p>
      </div>
    </div>
  </body>
</html>
              `,
        attachments: [
          {
            filename: 'logo.png',
            path: path.join(__dirname, '../../../', 'assets', 'logo.png'),
            cid: 'logo',
          },
        ],
      });
    } catch (error) {
      throw new HttpException(error.message, 500)
    }
  }

  async sendMailPasswordCreation(toEmail: string, link: string) {
    try {
      await this.mailerService.sendMail({
        to: toEmail,
        from: process.env.AWS_SENDER_EMAIL,
        subject: this.i18n.translate('common.mail.reset_password.subject', {args: {companyName: process.env.COMPANY_NAME}}),
        text: '',
        html: `
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OTP Verification Email</title>
    <style>
      /* Global styles */
      body {
        margin: 0;
        padding: 0;
        font-family: Arial, sans-serif;
        background-color: #f1f1f1;
      }

      /* Container styles */
      .container {
        max-width: 600px;
        margin: 0 auto;
        padding: 20px;
        background-color: #f1f1f1;
      }

      /* Logo styles */
      .logo {
        display: block;
        margin: 0 auto;
        width: 200px;
        margin-bottom: 2rem;
        margin-top: 2rem;
      }

      /* Card body styles */
      .card {
        background-color: #ffffff;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        border-radius: 6px;
        padding: 20px;
      }

      .card h1 {
        font-size: 24px;
        font-weight: bold;
        margin-bottom: 20px;
      }

      .card p {
        margin-bottom: 10px;
      }

      .otp {
        font-size: 36px;
        font-weight: bold;
        text-align: center;
        margin-bottom: 20px;
      }

      /* Footer styles */
      .footer {
        margin-top: 20px;
        text-align: center;
        color: #999999;
      }

      .footer p {
        margin-bottom: 5px;
        font-size: 12px;
      }
      .reset-link {
        background-color: #007bff;
        color: #fff !important;
        text-decoration: none;
        padding: 10px 15px;
        border-radius: 5px;
        display: inline-block;
        margin: 1rem auto;
      }

      .reset-link:hover {
        background-color: #0056b3;
        color: #fff !important;
      }
    </style>
</head>
<body>
  <div class="container">
    <!-- Logo -->
    <img class="logo" src="cid:logo" alt="Company Logo">

    <!-- Card Body -->
    <div class="card">
      <h1>Hello,</h1>
      <p>We received a request to reset your password for your account. If you did not make this request, you can safely ignore this email.</p>
      <p>If you want to reset your password, click the link below:</p>
      <p><a class="reset-link" href="${link}">Reset Password</a></p>
      <p>If the link does not work, you can copy and paste the following URL into your browser's address bar:</p>
      <p>${link}</p>
      <p>This link will expire in ${process.env.RESET_LINK_EXPIRE_HOURS} minutes.</p>
      <br/>
      
      <p>Thanks,</p>
      <b>The ${process.env.COMPANY_NAME} Customer Service Team</b>
    </div>

    <!-- Footer -->
    <div class="footer">
      <p style="font-style: italic;">Copyright @ 2023 ${process.env.COMPANY_NAME} LLC, All rights reserved.</p>
      <p>This message was sent by ${process.env.COMPANY_NAME} billing department. To change when and how you receive these emails please contact our billing team by phone at: ${process.env.COMPANY_PHONE} or via email at ${process.env.COMPANY_EMAIL}</p>
    </div>
  </div>
</body>
</html>`,
      attachments: [
          {
            filename: 'logo.png',
            path: path.join(__dirname, '../../../', 'assets', 'logo.png'),
            cid: 'logo',
          },
        ],
      });
    } catch (error) {
      throw new HttpException(error.message, 500)
    }
  }
}