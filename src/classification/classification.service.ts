import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { DeepPartial, Repository } from 'typeorm';
import { Classification } from './entities/classification.entity';
import { CreateClassificationDto } from './dto/create-classification.dto';
import { UpdateClassificationDto } from './dto/update-classification.dto';
import { Attribute } from 'src/attribute/entities/attribute.entity';
import { User } from 'src/user/entities/user.entity';
import { SoilType } from 'src/soil-type/entities/soil-type.entity';
import { Organization } from 'src/organization/entities/organization.entity';

@Injectable()
export class ClassificationService {
  constructor(
    @InjectRepository(Classification)
    private readonly classificationRepository: Repository<Classification>,
  ) {}

  async findAll(): Promise<Classification[]> {
    return this.classificationRepository.find({
      relations: ['attribute', 'user', 'soil_type', 'entity'],
    });
  }

  async findOne(id: string): Promise<Classification> {
    const classification = await this.classificationRepository.findOne({
      where: { id },
      relations: ['attribute', 'user', 'soil_type', 'entity'],
    });
    if (!classification)
      throw new NotFoundException(`Clasificación con ID ${id} no encontrada`);
    return classification;
  }

  async create(
    createClassificationDto: CreateClassificationDto,
  ): Promise<Classification> {
    const classification = this.classificationRepository.create({
      code: createClassificationDto.code,
      attribute: createClassificationDto.attribute
        ? ({ id: createClassificationDto.attribute } as DeepPartial<Attribute>)
        : undefined,
      user: createClassificationDto.user
        ? ({ id: createClassificationDto.user } as DeepPartial<User>)
        : undefined,
      soil_type: createClassificationDto.soil_type
        ? ({ id: createClassificationDto.soil_type } as DeepPartial<SoilType>)
        : undefined,
      organization: createClassificationDto.organization
        ? ({
            id: createClassificationDto.organization,
          } as DeepPartial<Organization>)
        : undefined,
    });

    await this.classificationRepository.save(classification);
    return classification;
  }

  async update(
    id: string,
    updateClassificationDto: UpdateClassificationDto,
  ): Promise<Classification> {
    const classification = await this.findOne(id);
    Object.assign(classification, updateClassificationDto);

    return this.classificationRepository.save(classification);
  }

  async remove(id: string): Promise<void> {
    const classification = await this.findOne(id);
    await this.classificationRepository.remove(classification);
  }
}
