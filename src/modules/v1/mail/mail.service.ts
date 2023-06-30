import { HttpException, Injectable } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';

@Injectable()
export class MailService {
  constructor(private readonly mailerService: MailerService) {}
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

  async sendMailCode(toEmail: string, otpCOde: number | string) {
    try {
      this.mailerService.sendMail({
        to: toEmail, // list of receivers
        from: process.env.AWS_SENDER_EMAIL, // sender address
        subject: `confirmation code`, // Subject of the email
        text: '', // plaintext body
        html: `
                <div>
                  ${`<div><<p>${otpCOde} is your authorization code for ${process.env.CLIENT_URL} ✔ </p><div>`}
                </div>
              `,
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
        subject: `Create a new password for your account ${process.env.APP_NAME} ✔`,
        text: '',
        html: `
        <div>
          ${`<div><p>Follow the link to reset your password: <a href=${link}&email=${toEmail}>Link</a></p><div>`}
        </div>
      `,
      });
    } catch (error) {
      throw new HttpException(error.message, 500)
    }
  }
}