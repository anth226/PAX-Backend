import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import { TokenExpiredError } from 'jsonwebtoken';
import { PRE_AUTH_TOKEN } from 'src/utils/constants';

@Injectable()
export class PreAuthGuard implements CanActivate {
  canActivate(context: ExecutionContext): any {
    const request = context.switchToHttp().getRequest();
    try {
      const authToken = request.cookies?.[PRE_AUTH_TOKEN];
      if (!authToken) {
        throw new UnauthorizedException('No Auth Token.');
      }
      request.user = jwt.verify(authToken, process.env.JWT_ACCESS_SECRET || 'SERCRET');
      return true;
    } catch (error) {
      const response = context.switchToHttp().getResponse();
      response.clearCookie(PRE_AUTH_TOKEN)
      if (error instanceof TokenExpiredError) {
        throw new UnauthorizedException('Login Session Expired. Please login again.');
      }
      if (error instanceof Error && error.message === 'No auth token') {
        throw new UnauthorizedException(error.message);
      }
      throw error || new UnauthorizedException();
    }
  }
}
