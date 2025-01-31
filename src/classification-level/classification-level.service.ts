import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ClassificationLevel } from './entities/classification-level.entity';
import { CreateClassificationLevelDto } from './dto/create-classification-level.dto';
import { UpdateClassificationLevelDto } from './dto/update-classification-level.dto';
import { Classification } from 'src/classification/entities/classification.entity';

@Injectable()
export class ClassificationLevelService {
  constructor(
    @InjectRepository(ClassificationLevel)
    private readonly classificationLevelRepository: Repository<ClassificationLevel>,
  ) {}

  async findAll(): Promise<ClassificationLevel[]> {
    return this.classificationLevelRepository.find({
      relations: ['classification'],
    });
  }

  async findOne(id: string): Promise<ClassificationLevel> {
    const classificationLevel =
      await this.classificationLevelRepository.findOne({
        where: { id },
        relations: ['classification'],
      });
    if (!classificationLevel)
      throw new NotFoundException(
        `Nivel de clasificación con ID ${id} no encontrado`,
      );
    return classificationLevel;
  }

  async create(
    createClassificationLevelDto: CreateClassificationLevelDto,
  ): Promise<ClassificationLevel> {
    const classificationLevel = this.classificationLevelRepository.create({
      ...createClassificationLevelDto,
      classification: {
        id: createClassificationLevelDto.classification,
      } as Classification,
    });

    await this.classificationLevelRepository.save(classificationLevel);
    return classificationLevel;
  }

  async update(
    id: string,
    updateClassificationLevelDto: UpdateClassificationLevelDto,
  ): Promise<ClassificationLevel> {
    const classificationLevel = await this.findOne(id);
    Object.assign(classificationLevel, updateClassificationLevelDto);

    return this.classificationLevelRepository.save(classificationLevel);
  }

  async remove(id: string): Promise<void> {
    const classificationLevel = await this.findOne(id);
    await this.classificationLevelRepository.remove(classificationLevel);
  }
}
