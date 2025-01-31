import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Attribute } from './entities/attribute.entity';
import { CreateAttributeDto } from './dto/create-attribute.dto';
import { UpdateAttributeDto } from './dto/update-attribute.dto';
import { UnitMeasure } from 'src/unit-measure/entities/unit-measure.entity';

@Injectable()
export class AttributeService {
  constructor(
    @InjectRepository(Attribute)
    private readonly attributeRepository: Repository<Attribute>,
  ) {}

  async findAll(): Promise<Attribute[]> {
    return this.attributeRepository.find({ relations: ['unit'] });
  }

  async findOne(id: string): Promise<Attribute> {
    const attribute = await this.attributeRepository.findOne({
      where: { id },
      relations: ['unit'],
    });
    if (!attribute)
      throw new NotFoundException(`Atributo con ID ${id} no encontrado`);
    return attribute;
  }

  async create(createAttributeDto: CreateAttributeDto): Promise<Attribute> {
    const attribute = this.attributeRepository.create({
      ...createAttributeDto,
      unit: createAttributeDto.unit
        ? ({ id: createAttributeDto.unit } as UnitMeasure)
        : undefined,
    });

    await this.attributeRepository.save(attribute);
    return attribute;
  }

  async update(
    id: string,
    updateAttributeDto: UpdateAttributeDto,
  ): Promise<Attribute> {
    const attribute = await this.findOne(id);
    Object.assign(attribute, updateAttributeDto);

    return this.attributeRepository.save(attribute);
  }

  async remove(id: string): Promise<void> {
    const attribute = await this.findOne(id);
    await this.attributeRepository.remove(attribute);
  }
}
