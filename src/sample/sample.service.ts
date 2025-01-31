import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Sample } from './entities/sample.entity';
import { CreateSampleDto } from './dto/create-sample.dto';
import { UpdateSampleDto } from './dto/update-sample.dto';
import { parse } from 'wellknown';
import { Geometry } from 'geojson';
import { Area } from 'src/area/entities/area.entity';
import { User } from 'src/user/entities/user.entity';

@Injectable()
export class SampleService {
  constructor(
    @InjectRepository(Sample)
    private readonly sampleRepository: Repository<Sample>,
  ) {}

  async findAll(): Promise<Sample[]> {
    return this.sampleRepository.find({ relations: ['area', 'user'] });
  }

  async findOne(id: string): Promise<Sample> {
    const sample = await this.sampleRepository.findOne({
      where: { id },
      relations: ['area', 'user'],
    });
    if (!sample)
      throw new NotFoundException(`Muestra con ID ${id} no encontrada`);
    return sample;
  }

  async create(createSampleDto: CreateSampleDto): Promise<Sample> {
    const sample = this.sampleRepository.create({
      ...createSampleDto,
      geom: parse(createSampleDto.geom) as Geometry,
      area: { id: createSampleDto.area } as Area,
      user: { id: createSampleDto.user } as User,
    });

    await this.sampleRepository.save(sample);
    return sample;
  }

  async update(id: string, updateSampleDto: UpdateSampleDto): Promise<Sample> {
    const sample = await this.findOne(id);
    Object.assign(sample, updateSampleDto);

    if (updateSampleDto.geom) {
      sample.geom = parse(updateSampleDto.geom) as Geometry;
    }

    return this.sampleRepository.save(sample);
  }

  async remove(id: string): Promise<void> {
    const sample = await this.findOne(id);
    await this.sampleRepository.remove(sample);
  }
}
