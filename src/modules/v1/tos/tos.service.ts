import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Request } from 'express';
import { I18nTranslations } from 'src/generated/i18n.generated';
import { I18nService } from 'nestjs-i18n';
import { TOSTextDto } from './entity/dto/tos.dto';
import { TOSTextEntity } from './entity/tos.entity';
import { UserEntity } from '../users/entity/user.entity';
import { TOSAcceptanceEntity } from './entity/tos-acceptance.entity';
import { LoggingService } from '../auth/login-logging.service';
import { AuthService } from '../auth/auth.service';

@Injectable()
export class TOSTextService {
  constructor(
    @InjectRepository(TOSTextEntity) private readonly tosTextModel: Repository<TOSTextEntity>,
    @InjectRepository(UserEntity) private readonly userModel: Repository<UserEntity>,
    @InjectRepository(TOSAcceptanceEntity)
    private readonly tosAcceptanceModel: Repository<TOSAcceptanceEntity>,
    private readonly authService: AuthService,
    private readonly loggingService: LoggingService,
    private readonly i18n: I18nService<I18nTranslations>,
  ) {}

  async createTOSText(createTOSTextDto: TOSTextDto): Promise<TOSTextEntity> {
    const { text } = createTOSTextDto;

    const tosText = new TOSTextEntity();
    tosText.text = text;
    const createdTOSText = await this.tosTextModel.save(tosText);
    return createdTOSText;
  }

  async acceptLatestTos(req: any, ip: string, ua: string, method: string) {
    const user = await this.userModel.findOneBy({ id: req.user?.id });
    if (!user) {
      throw new BadRequestException({
        message: this.i18n.translate('common.auth.invalid_id'),
      });
    }
    const tosText = await this.tosTextModel.findOne({ where: {}, order: { createdAt: 'DESC' } });
    if (!tosText) {
      throw new BadRequestException({
        message: this.i18n.translate('common.tos.no_tos'),
      });
    }
    await this.tosAcceptanceModel.insert({
      user,
      tosText,
    });
    user.hasAcceptedLatestTOS = true;
    await user.save();
    await this.loggingService.logSuccessfulLogin(user, ip, ua, method, false);
    const userDataAndTokens = await this.authService.tokenSession(req, user, ip);
    return userDataAndTokens;
  }
}
