import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import { TokenExpiredError } from 'jsonwebtoken';

@Injectable()
export class PreAuthGuard implements CanActivate {
  canActivate(
    context: ExecutionContext,
  ): any {
        try {
            const request = context.switchToHttp().getRequest();
            const authToken = request.cookies.pre_auth_token;
            if(!authToken) {
                throw new UnauthorizedException("No Auth Token.");
            }
            request.user = jwt.verify(authToken, process.env.JWT_ACCESS_SECRET || 'SERCRET');
            return true;
        } catch (error) {
            if (error instanceof TokenExpiredError) {
                throw new UnauthorizedException("Login Session Expired. Please login again.")
            }
            if (error instanceof Error && error.message === 'No auth token') {
                throw new UnauthorizedException(error.message)
            }
            throw error || new UnauthorizedException();
        }
    }
}
