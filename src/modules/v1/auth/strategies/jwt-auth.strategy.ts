import { ExtractJwt, Strategy } from 'passport-jwt'
import { PassportStrategy } from '@nestjs/passport'
import { HttpException, HttpStatus, Injectable } from '@nestjs/common'
import { Request } from 'express'
import { UserService } from '../../users/users.service'

export type JwtAccessPayload = {
    id: string | number;
    displayName: string 
}

@Injectable()
export class JwtAuthStrategy extends PassportStrategy(Strategy) {
    
    constructor(
        private readonly userService: UserService
    ) {
        super({
            jwtFromRequest: JwtAuthStrategy.extractJwtFromCookie,
            ignoreExpiration: false,
            secretOrKey: process.env.JWT_ACCESS_SECRET || 'SERCRET',
        })
    }

    static extractJwtFromCookie(req: Request) {
        let token = null

        if (req && req.cookies) {
            token = req.cookies['access_token']
        }
        
        return token || ExtractJwt.fromAuthHeaderAsBearerToken()(req)
    }

    async validate(payload: JwtAccessPayload) {
        //const user = await this.userService.getUserByField('id', payload.id)
        if (!payload && !payload.id) {
            throw new HttpException('Invalid token', HttpStatus.UNAUTHORIZED);
        }
        return payload
    }
}