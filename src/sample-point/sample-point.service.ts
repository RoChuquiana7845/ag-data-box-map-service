import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { SamplePoint } from './entities/sample-point.entity';
import { CreateSamplePointDto } from './dto/create-sample-point.dto';
import { UpdateSamplePointDto } from './dto/update-sample-point.dto';
import { parse } from 'wellknown';
import { Geometry } from 'geojson';
import { SampleGrid } from 'src/sample-grid/entities/sample-grid.entity';

@Injectable()
export class SamplePointService {
  constructor(
    @InjectRepository(SamplePoint)
    private readonly samplePointRepository: Repository<SamplePoint>,
  ) {}

  async findAll(): Promise<SamplePoint[]> {
    return this.samplePointRepository.find({ relations: ['sample_grid'] });
  }

  async findOne(id: string): Promise<SamplePoint> {
    const point = await this.samplePointRepository.findOne({
      where: { id },
      relations: ['sample_grid'],
    });
    if (!point)
      throw new NotFoundException(
        `Punto de muestreo con ID ${id} no encontrado`,
      );
    return point;
  }

  async create(
    createSamplePointDto: CreateSamplePointDto,
  ): Promise<SamplePoint> {
    const point = this.samplePointRepository.create({
      ...createSamplePointDto,
      geom: parse(createSamplePointDto.geom) as Geometry,
      sample_grid: { id: createSamplePointDto.sample_grid } as SampleGrid,
    });

    await this.samplePointRepository.save(point);
    return point;
  }

  async update(
    id: string,
    updateSamplePointDto: UpdateSamplePointDto,
  ): Promise<SamplePoint> {
    const point = await this.findOne(id);
    Object.assign(point, updateSamplePointDto);

    if (updateSamplePointDto.geom) {
      point.geom = parse(updateSamplePointDto.geom) as Geometry;
    }

    return this.samplePointRepository.save(point);
  }

  async remove(id: string): Promise<void> {
    const point = await this.findOne(id);
    await this.samplePointRepository.remove(point);
  }
}
