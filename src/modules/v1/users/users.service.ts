import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { from, toArray } from 'rxjs';
import { UserEntity } from './entity/user.entity';
import { Repository } from 'typeorm';


@Injectable()
export class UserService {
    constructor(
    @InjectRepository(UserEntity) private readonly userModel: Repository<UserEntity>
    ){}

    public async getUserByField(field: string, value: string | number) {
        const user = await this.userModel.findOne({ where: { [field]: value } })
        return user
    }
}