import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Map } from './entities/map.entity';
import { CreateMapDto } from './dto/create-map.dto';
import { UpdateMapDto } from './dto/update-map.dto';
import { parse } from 'wellknown';
import { Geometry } from 'geojson';
import { User } from 'src/auth/entities/user.entity';
import { Area } from 'src/area/entities/area.entity';

@Injectable()
export class MapService {
  constructor(
    @InjectRepository(Map)
    private readonly mapRepository: Repository<Map>,
  ) {}

  async findAll(): Promise<Map[]> {
    return this.mapRepository.find({ relations: ['user', 'area'] });
  }

  async findOne(id: string): Promise<Map> {
    const map = await this.mapRepository.findOne({
      where: { id },
      relations: ['user', 'area'],
    });
    if (!map) throw new NotFoundException(`Mapa con ID ${id} no encontrado`);
    return map;
  }

  async create(createMapDto: CreateMapDto): Promise<Map> {
    const map = this.mapRepository.create({
      ...createMapDto,
      geom: parse(createMapDto.geom) as Geometry,
      user: { id: createMapDto.user } as User,
      area: createMapDto.area ? ({ id: createMapDto.area } as Area) : {},
    });

    await this.mapRepository.save(map);
    return map;
  }

  async update(id: string, updateMapDto: UpdateMapDto): Promise<Map> {
    const map = await this.findOne(id);
    Object.assign(map, updateMapDto);

    if (updateMapDto.geom) {
      map.geom = parse(updateMapDto.geom) as Geometry;
    }

    return this.mapRepository.save(map);
  }

  async remove(id: string): Promise<void> {
    const map = await this.findOne(id);
    await this.mapRepository.remove(map);
  }
}
