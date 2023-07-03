import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { TOSTextDto } from './entity/dto/tos.dto';
import { TOSTextEntity } from './entity/tos.entity';

@Injectable()
export class TOSTextService {
  constructor(
    @InjectRepository(TOSTextEntity)
    private readonly tosTextModel: Repository<TOSTextEntity>,
  ) {}

  async createTOSText(createTOSTextDto: TOSTextDto): Promise<TOSTextEntity> {
    const { text } = createTOSTextDto;

    const tosText = new TOSTextEntity();
    tosText.text = text;
    const createdTOSText = await this.tosTextModel.save(tosText);
    return createdTOSText;
  }
}
