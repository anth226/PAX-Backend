import { ErrorHandle } from 'src/exceptions/ErrorHandle';
import { TOSTextDto } from './entity/dto/tos.dto';
import { TOSTextEntity } from './entity/tos.entity';
import { TOSTextService } from './tos.service';
import { Controller, Post, Body } from '@nestjs/common';

@Controller('tos')
export class TOSTextController {
    constructor(private readonly tosTextService: TOSTextService) {}
    
    @Post()
    async createTOSText(@Body() createTOSTextDto: TOSTextDto): Promise<TOSTextEntity> {
        try {
            const createdTOSText = await this.tosTextService.createTOSText(createTOSTextDto);
            return createdTOSText;
        } catch (error) {
            return ErrorHandle(error)
        }
    }
}