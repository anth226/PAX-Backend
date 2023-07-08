import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString, Matches } from 'class-validator';
import { Match } from 'src/custom-decorators/match.decorator';
import { DecryptPasswordsAndValidate } from '../../../../../custom-decorators/decrypt-passwords-validate.decorator';
import { PasswordComplexity } from '../../../../../custom-decorators/password-complexity.decorator';

export class ChangePasswordDto {
  @ApiProperty({ example: '111slldfe', description: 'Reset Link Code' })
  @IsString()
  reset_code: string;

  @ApiProperty({ example: 'jgdffvcdff', description: 'New Password crypto encrypted' })
  @IsString()
  password: string;

  @ApiProperty({
    example: 'kkuhfffgvvcffffff',
    description: 'Confirmation Password crypto encrypted',
  })
  @IsString()
  confirm_password: string;
}
