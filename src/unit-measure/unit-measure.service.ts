import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { UnitMeasure } from './entities/unit-measure.entity';
import { CreateUnitMeasureDto } from './dto/create-unit-measure.dto';
import { UpdateUnitMeasureDto } from './dto/update-unit-measure.dto';
import { User } from 'src/user/entities/user.entity';

@Injectable()
export class UnitMeasureService {
  constructor(
    @InjectRepository(UnitMeasure)
    private readonly unitMeasureRepository: Repository<UnitMeasure>,
  ) {}

  async findAll(): Promise<UnitMeasure[]> {
    return this.unitMeasureRepository.find({ relations: ['user'] });
  }

  async findOne(id: string): Promise<UnitMeasure> {
    const unitMeasure = await this.unitMeasureRepository.findOne({
      where: { id },
      relations: ['user'],
    });
    if (!unitMeasure)
      throw new NotFoundException(
        `Unidad de medida con ID ${id} no encontrada`,
      );
    return unitMeasure;
  }

  async create(
    createUnitMeasureDto: CreateUnitMeasureDto,
  ): Promise<UnitMeasure> {
    const unitMeasure = this.unitMeasureRepository.create({
      ...createUnitMeasureDto,
      user: { id: createUnitMeasureDto.user } as User,
    });

    await this.unitMeasureRepository.save(unitMeasure);
    return unitMeasure;
  }

  async update(
    id: string,
    updateUnitMeasureDto: UpdateUnitMeasureDto,
  ): Promise<UnitMeasure> {
    const unitMeasure = await this.findOne(id);
    Object.assign(unitMeasure, updateUnitMeasureDto);

    return this.unitMeasureRepository.save(unitMeasure);
  }

  async remove(id: string): Promise<void> {
    const unitMeasure = await this.findOne(id);
    await this.unitMeasureRepository.remove(unitMeasure);
  }
}
