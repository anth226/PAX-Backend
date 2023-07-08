import {
  registerDecorator,
  ValidationOptions,
  ValidatorConstraint,
  ValidatorConstraintInterface,
  ValidationArguments,
} from 'class-validator';
import { BadRequestException } from '@nestjs/common';

const CryptoJS = require('crypto-js');

@ValidatorConstraint({ name: 'passwordComplexity', async: false })
export class PasswordComplexityConstraint implements ValidatorConstraintInterface {
  validate(value: string, args: ValidationArguments) {
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]{8,}$/;
    const decryptedValue = CryptoJS.AES.decrypt(
      value,
      process.env.PASSWORD_DECRYPTION_KEY ?? '',
    ).toString(CryptoJS.enc.Utf8);
    if (!decryptedValue) {
      throw new BadRequestException('Password is not in right format.');
    }
    return passwordRegex.test(decryptedValue);
  }

  defaultMessage(args: ValidationArguments) {
    return 'Password must contain at least 8 characters, one uppercase letter, one lowercase letter, one number, and one special character.';
  }
}

export function PasswordComplexity(validationOptions?: ValidationOptions) {
  return function (object: Object, propertyName: string) {
    registerDecorator({
      target: object.constructor,
      propertyName,
      options: validationOptions,
      constraints: [],
      validator: PasswordComplexityConstraint,
    });
  };
}
