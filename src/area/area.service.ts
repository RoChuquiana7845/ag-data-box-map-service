import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { DataSource, Geometry, Repository } from 'typeorm';
import { Area } from './entities/area.entity';
import { CreateAreaDto } from './dto/create-area.dto';
import { UpdateAreaDto } from './dto/update-area.dto';
import { parse } from 'wellknown';
import { User } from 'src/auth/entities/user.entity';

@Injectable()
export class AreaService {
  constructor(
    @InjectRepository(Area)
    private readonly areaRepository: Repository<Area>,
    private readonly datasource: DataSource,
  ) {}

  async findAll(): Promise<Area[]> {
    return this.areaRepository.find({ relations: ['user', 'samples'] });
  }

  async findOne(id: string): Promise<Area> {
    const area = await this.areaRepository.findOne({
      where: { id },
      relations: ['user'],
    });
    if (!area) throw new NotFoundException(`Área con ID ${id} no encontrada`);
    return area;
  }

  async create(createAreaDto: CreateAreaDto): Promise<Area> {
    const area = this.areaRepository.create({
      ...createAreaDto,
      geom: parse(createAreaDto.geom) as Geometry,
      user: { id: createAreaDto.user } as User,
    });

    await this.areaRepository.save(area);
    return area;
  }

  async update(id: string, updateAreaDto: UpdateAreaDto): Promise<Area> {
    const area = await this.findOne(id);
    Object.assign(area, updateAreaDto);

    if (updateAreaDto.geom) {
      area.geom = parse(updateAreaDto.geom) as Geometry;
    }

    return this.areaRepository.save(area);
  }

  async remove(id: string): Promise<void> {
    const area = await this.findOne(id);
    await this.areaRepository.remove(area);
  }
}
