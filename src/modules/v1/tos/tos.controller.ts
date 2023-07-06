import { ErrorHandle } from 'src/exceptions/ErrorHandle';
import { TOSTextDto } from './entity/dto/tos.dto';
import { TOSTextEntity } from './entity/tos.entity';
import { TOSTextService } from './tos.service';
import { Controller, Post, Body, UseGuards, Req, Res, Ip, Headers } from '@nestjs/common';
import { PreAuthGuard } from 'src/guards/pre-auth.guard';
import {Request, Response} from 'express'

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

    @Post("/accept")
    @UseGuards(PreAuthGuard)
    async acceptLatestTos(
        @Body() dto: any,
        @Req() req: Request,
        @Ip() ip: any,
        @Headers() headers: Record <string, string>
    ) {
        try {
            const ua = headers['user-agent'];
            const method = req.method
            return this.tosTextService.acceptLatestTos(req, ip, ua, method)
        } catch (error) {
            return ErrorHandle(error)
        }
    }
}