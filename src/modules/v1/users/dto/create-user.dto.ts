import { ApiProperty } from "@nestjs/swagger";
import { IsEmail, IsOptional, IsString } from "class-validator";
import {PasswordComplexity} from '../../../../custom-decorators/password-complexity.decorator'

export class CreateUserDto {

  @ApiProperty({description: "Login Email", example: "admin@example.com"})
  @IsEmail()
  readonly email: string;

  @ApiProperty({description: "Login Password", example: "123456aA#"})
  @IsString()
  @PasswordComplexity()
  readonly password: string;

  @ApiProperty({description: "Phone Number", example: "+1XXXXXXXXX"})
  @IsOptional()
  readonly phone: string;
}