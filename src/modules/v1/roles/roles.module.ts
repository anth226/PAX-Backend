import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { RoleService } from './roles.service';
import { RoleController } from './roles.controller';
import { RoleEntity } from './entity/role.entity';
import { UserRoleEntity } from './entity/user-role.entity';
import { UserEntity } from '../users/entity/user.entity';

@Module({
  providers: [RoleService],
  controllers: [RoleController],
  imports: [TypeOrmModule.forFeature([RoleEntity, UserRoleEntity, UserEntity])],
  exports: [RoleService],
})
export class RolesModule {}
