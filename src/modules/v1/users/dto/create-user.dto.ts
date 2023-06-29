import { ApiProperty } from "@nestjs/swagger";

export class CreateUserDto {
  @ApiProperty({description: "Login Email", example: "admin@example.com"})
  readonly email: string;
  @ApiProperty({description: "Login Password", example: "123456"})
  readonly password: string;
}