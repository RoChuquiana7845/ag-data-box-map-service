import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { SampleGrid } from './entities/sample-grid.entity';
import { CreateSampleGridDto } from './dto/create-sample-grid.dto';
import { UpdateSampleGridDto } from './dto/update-sample-grid.dto';
import { parse } from 'wellknown';
import { Geometry } from 'geojson';
import { Area } from 'src/area/entities/area.entity';
import { User } from 'src/user/entities/user.entity';

@Injectable()
export class SampleGridService {
  constructor(
    @InjectRepository(SampleGrid)
    private readonly sampleGridRepository: Repository<SampleGrid>,
  ) {}

  async findAll(): Promise<SampleGrid[]> {
    return this.sampleGridRepository.find({ relations: ['area', 'user'] });
  }

  async findOne(id: string): Promise<SampleGrid> {
    const grid = await this.sampleGridRepository.findOne({
      where: { id },
      relations: ['area', 'user'],
    });
    if (!grid) throw new NotFoundException(`Grilla con ID ${id} no encontrada`);
    return grid;
  }

  async create(createSampleGridDto: CreateSampleGridDto): Promise<SampleGrid> {
    const grid = this.sampleGridRepository.create({
      ...createSampleGridDto,
      geom: parse(createSampleGridDto.geom) as Geometry,
      area: { id: createSampleGridDto.area } as Area,
      user: { id: createSampleGridDto.user } as User,
    });

    await this.sampleGridRepository.save(grid);
    return grid;
  }

  async update(
    id: string,
    updateSampleGridDto: UpdateSampleGridDto,
  ): Promise<SampleGrid> {
    const grid = await this.findOne(id);
    Object.assign(grid, updateSampleGridDto);

    if (updateSampleGridDto.geom) {
      grid.geom = parse(updateSampleGridDto.geom) as Geometry;
    }

    return this.sampleGridRepository.save(grid);
  }

  async remove(id: string): Promise<void> {
    const grid = await this.findOne(id);
    await this.sampleGridRepository.remove(grid);
  }
}
