import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { TokenExpiredError } from 'jsonwebtoken';
import { ExecutionContext } from '@nestjs/common/interfaces';
import { AuthService } from 'src/modules/v1/auth/auth.service';
import { Observable } from 'rxjs';
import { ExtractJwt } from 'passport-jwt';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(private readonly authService: AuthService) {
    super();
  }

  handleRequest(err, user, info, context) {
    if (!user) {
      const { message } = info;
      if (info instanceof TokenExpiredError) {
        throw new UnauthorizedException(message)
      }
      if (info instanceof Error && message === 'No auth token') {
        throw new UnauthorizedException(message)
      }
    }

    if (err || !user) {
      throw err || new UnauthorizedException();
    }

    return user;
  }

  private getRefreshTokenFromRequest(request): string {
    return request?.cookies?.refresh_token;
  }
}
