import { Controller, Get, Render } from '@nestjs/common';
import { RoleService } from './roles.service';

@Controller()
export class RoleController {
  constructor(private readonly appService: RoleService) {}
}
