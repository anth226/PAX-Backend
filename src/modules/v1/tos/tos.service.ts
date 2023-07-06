import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { TOSTextDto } from './entity/dto/tos.dto';
import { TOSTextEntity } from './entity/tos.entity';
import {Request} from 'express'
import { UserEntity } from '../users/entity/user.entity';
import { TOSAcceptanceEntity } from './entity/tos-acceptance.entity';
import { LoggingService } from '../auth/login-logging.service';
import { AuthService } from '../auth/auth.service';

@Injectable()
export class TOSTextService {
  constructor(
    @InjectRepository(TOSTextEntity) private readonly tosTextModel: Repository<TOSTextEntity>,
    @InjectRepository(UserEntity) private readonly userModel: Repository<UserEntity>,
    @InjectRepository(TOSAcceptanceEntity) private readonly tosAcceptanceModel: Repository<TOSAcceptanceEntity>,
    private readonly authService: AuthService,
    private readonly loggingService: LoggingService,
  ) {}

  async createTOSText(createTOSTextDto: TOSTextDto): Promise<TOSTextEntity> {
    const { text } = createTOSTextDto;

    const tosText = new TOSTextEntity();
    tosText.text = text;
    const createdTOSText = await this.tosTextModel.save(tosText);
    return createdTOSText;
  }

  async acceptLatestTos(req: any, ip: string, ua: string, method: string) {
    const user = await this.userModel.findOneBy({id:  req.user?.id})
    if(!user) {
        throw new BadRequestException({
            message: 'The user with the given ID is not in the database',
        });
    }
    const tosText = await this.tosTextModel.findOne({where:{}, order: {createdAt: 'DESC'}})
    if(!tosText) {
      throw new BadRequestException({
            message: 'No TOS entry found in the database.',
      });
    }
    await this.tosAcceptanceModel.insert({
      user: user,
      tosText: tosText
    })
    await this.loggingService.logSuccessfulLogin(user, ip, ua, method, false)
    const userDataAndTokens = await this.authService.tokenSession(req, user, ip);
    return userDataAndTokens;
  }

}
