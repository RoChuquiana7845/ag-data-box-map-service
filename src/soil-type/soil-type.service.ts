import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { SoilType } from './entities/soil-type.entity';
import { CreateSoilTypeDto } from './dto/create-soil-type.dto';
import { UpdateSoilTypeDto } from './dto/update-soil-type.dto';
import { User } from 'src/user/entities/user.entity';

@Injectable()
export class SoilTypeService {
  constructor(
    @InjectRepository(SoilType)
    private readonly soilTypeRepository: Repository<SoilType>,
  ) {}

  async findAll(): Promise<SoilType[]> {
    return this.soilTypeRepository.find({ relations: ['user'] });
  }

  async findOne(id: string): Promise<SoilType> {
    const soilType = await this.soilTypeRepository.findOne({
      where: { id },
      relations: ['user'],
    });
    if (!soilType)
      throw new NotFoundException(`Tipo de suelo con ID ${id} no encontrado`);
    return soilType;
  }

  async create(createSoilTypeDto: CreateSoilTypeDto): Promise<SoilType> {
    const soilType = this.soilTypeRepository.create({
      ...createSoilTypeDto,
      user: { id: createSoilTypeDto.user } as User,
    });

    await this.soilTypeRepository.save(soilType);
    return soilType;
  }

  async update(
    id: string,
    updateSoilTypeDto: UpdateSoilTypeDto,
  ): Promise<SoilType> {
    const soilType = await this.findOne(id);
    Object.assign(soilType, updateSoilTypeDto);

    return this.soilTypeRepository.save(soilType);
  }

  async remove(id: string): Promise<void> {
    const soilType = await this.findOne(id);
    await this.soilTypeRepository.remove(soilType);
  }
}
