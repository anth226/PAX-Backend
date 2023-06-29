import { ApiProperty } from '@nestjs/swagger';
import { HttpStatus } from '@nestjs/common';
import { UserDto } from 'src/modules/v1/users/dto/user.dto';

export class LoginResponseDto {
  @ApiProperty({
    description: 'The HTTP status code of the response',
    example: HttpStatus.OK,
  })
  statusCode: HttpStatus;

  @ApiProperty({
    description: 'A message describing the response',
    example: 'Authentication successful',
  })
  message: string;

  @ApiProperty({
    description: 'The access token for authentication',
    example: 'abcde12345',
  })
  accessToken: string;

  @ApiProperty({
    description: 'The refresh token for authentication',
    example: 'fghij67890',
  })
  refreshToken: string;

  @ApiProperty({
    description: 'The user object containing user data',
    type: UserDto,
  })
  user: UserDto;
}
