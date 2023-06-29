import { HttpException, Injectable } from '@nestjs/common';
import { TwilioClient } from 'nestjs-twilio';

@Injectable()
export class PhoneService {
  constructor(private readonly client: TwilioClient) {}
  async sendPhoneSMS(TARGET_PHONE_NUMBER: string) {
    try {
      return await this.client.messages.create({
        body: `SMS Body, sent to the phone! ${TARGET_PHONE_NUMBER}`,
        from: process.env.TWILIO_PHONE_NUMBER, // format +14177544075
        to: '+' + TARGET_PHONE_NUMBER,
      });
    } catch (error) {
        throw new HttpException(error.message, 500)
    }
  }

  // we receive a code and a phone number from the user in order to verify the correctness and verify the user
  async verify(TARGET_PHONE_NUMBER: string, code: string) {
    try {
      return this.client.verify.v2.services(process.env.TWILIO_SERVICE_SID).verificationChecks.create({
        to: `+${TARGET_PHONE_NUMBER}`,
        code: code, // the default expiration date is 10 minutes
      });
    } catch (error) {
      throw new HttpException(error.message, 500)
    }
  }
}