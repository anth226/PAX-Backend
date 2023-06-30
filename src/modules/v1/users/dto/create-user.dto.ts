import { ApiProperty } from "@nestjs/swagger";
import { IsEmail, IsString } from "class-validator";

export class CreateUserDto {

  @ApiProperty({description: "Login Email", example: "admin@example.com"})
  @IsEmail()
  readonly email: string;

  @ApiProperty({description: "Login Password", example: "123456"})
  @IsString()
  readonly password: string;
}