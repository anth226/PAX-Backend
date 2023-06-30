import { HttpException, Injectable, Inject } from '@nestjs/common';
import {SNS} from 'aws-sdk'

@Injectable()
export class PhoneService {
  private snsService: SNS;
  constructor() {
    this.snsService = new SNS({
        accessKeyId: process.env.AWS_ACCESS_KEY,
        secretAccessKey: process.env.AWS_SECRET_KEY,
        region: process.env.AWS_REGION,
    })
  }
  async sendPhoneSMS(TARGET_PHONE_NUMBER: string, MESSAGE: string) {
    try {
      const params = {
        Message: MESSAGE,
        PhoneNumber: TARGET_PHONE_NUMBER,
      };
      return await this.snsService.publish(params).promise()
    } catch (error) {
      console.log(error)
        throw new HttpException(error.message, 500)
    }
  }

  // we receive a code and a phone number from the user in order to verify the correctness and verify the user
  async verify(TARGET_PHONE_NUMBER: string, code: string) {
    // try {
    //   return this.sns.verify.v2.services(process.env.TWILIO_SERVICE_SID).verificationChecks.create({
    //     to: `+${TARGET_PHONE_NUMBER}`,
    //     code: code, // the default expiration date is 10 minutes
    //   });
    // } catch (error) {
    //   throw new HttpException(error.message, 500)
    // }
  }
}