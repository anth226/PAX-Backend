import { createParamDecorator, ExecutionContext, BadRequestException } from '@nestjs/common';
import { plainToClass } from 'class-transformer';
import { validateSync } from 'class-validator';
import { ChangePasswordDto } from '../modules/v1/auth/entity/dto/change-password.dto';

const CryptoJS = require('crypto-js');

export const DecryptPasswordsAndValidate: any = createParamDecorator(
  async (data: unknown, ctx: ExecutionContext): Promise<any> => {
    const request = ctx.switchToHttp().getRequest();
    const encryptedDto = { ...request.body };

    // Decrypt the password and confirm_password fields
    const decryptedPassword = CryptoJS.AES.decrypt(
      encryptedDto.password,
      process.env.PASSWORD_DECRYPTION_KEY ?? '',
    ).toString(CryptoJS.enc.Utf8);
    const decryptedConfirmPassword = CryptoJS.AES.decrypt(
      encryptedDto.confirm_password,
      process.env.PASSWORD_DECRYPTION_KEY ?? '',
    ).toString(CryptoJS.enc.Utf8);
    if (!decryptedPassword) {
      throw new BadRequestException('Password is not in right format.');
    }

    if (!decryptedConfirmPassword) {
      throw new BadRequestException('Confirm Password is not in right format.');
    }

    // Replace the encrypted values with decrypted values
    encryptedDto.password = decryptedPassword;
    encryptedDto.confirm_password = decryptedConfirmPassword;

    // Validate the decrypted DTO against the original class validator rules
    const decryptedDto = plainToClass(ChangePasswordDto, encryptedDto, {
      excludeExtraneousValues: true,
    });

    // Validate the decrypted DTO using class-validator
    const validationErrors = validateSync(decryptedDto);
    if (validationErrors.length > 0) {
      throw new BadRequestException(validationErrors);
    }

    // Manually validate the password and confirm_password fields
    if (decryptedDto.password !== decryptedDto.confirm_password) {
      throw new BadRequestException('Password and Confirm Password do not match');
    }

    return decryptedDto;
  },
);
