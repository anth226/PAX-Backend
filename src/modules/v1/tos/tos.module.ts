import { Module } from '@nestjs/common';
import { TOSTextController } from './tos.controller';
import { TOSTextService } from './tos.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { TOSTextEntity } from './entity/tos.entity';
import { UserEntity } from '../users/entity/user.entity';
import { TOSAcceptanceEntity } from './entity/tos-acceptance.entity';
import { LoggingService } from '../auth/login-logging.service';
import { AuthService } from '../auth/auth.service';
import { LoginLogEntity } from '../auth/entity/login-logging.entity';
import { RefreshTokenSessionsEntity } from '../auth/entity/refresh-token.entity';
import { UserRoleEntity } from '../roles/entity/user-role.entity';
import { RoleEntity } from '../roles/entity/role.entity';
import { OTPEntity } from '../auth/entity/otp.entity';
import { LoginAttemptEntity } from '../auth/entity/login-attempt.entity';
import { TwoFactorMethodEntity } from '../auth/entity/two-factor.entity';
import { RoleService } from '../roles/roles.service';
import { MailService } from '../mail/mail.service';
import { PhoneService } from '../phone/phone.service';
import { JwtAuthStrategy } from '../auth/strategies/jwt-auth.strategy';
import { JwtService } from '@nestjs/jwt';

@Module({
  providers: [TOSTextService, AuthService, LoggingService, JwtService, MailService, PhoneService],
  controllers: [TOSTextController],
  imports: [
    TypeOrmModule.forFeature([
      TOSTextEntity,
      UserEntity,
      TOSAcceptanceEntity,
      RefreshTokenSessionsEntity,
      UserRoleEntity,
      RoleEntity,
      OTPEntity,
      LoginAttemptEntity,
      LoginLogEntity,
      TwoFactorMethodEntity
      
    ])
  ],
  exports: [TOSTextService],
})
export class TOSTextModule {}