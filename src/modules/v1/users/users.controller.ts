import { Controller, Get, Render } from '@nestjs/common';
import { UserService } from './users.service';

@Controller()
export class UserController {
  constructor(private readonly appService: UserService) {}
}
