import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { PixelMap } from './entities/pixel-map.entity';
import { CreatePixelMapDto } from './dto/create-pixel-map.dto';
import { UpdatePixelMapDto } from './dto/update-pixel-map.dto';
import { parse } from 'wellknown';
import { Geometry } from 'geojson';
import { Map } from 'src/map/entities/map.entity';

@Injectable()
export class PixelMapService {
  constructor(
    @InjectRepository(PixelMap)
    private readonly pixelMapRepository: Repository<PixelMap>,
  ) {}

  async findAll(): Promise<PixelMap[]> {
    return this.pixelMapRepository.find({ relations: ['map'] });
  }

  async findOne(id: string): Promise<PixelMap> {
    const pixel = await this.pixelMapRepository.findOne({
      where: { id },
      relations: ['map'],
    });
    if (!pixel)
      throw new NotFoundException(
        `Píxel en el mapa con ID ${id} no encontrado`,
      );
    return pixel;
  }

  async create(createPixelMapDto: CreatePixelMapDto): Promise<PixelMap> {
    const pixel = this.pixelMapRepository.create({
      ...createPixelMapDto,
      geom: parse(createPixelMapDto.geom) as Geometry,
      map: { id: createPixelMapDto.map } as Map,
    });

    await this.pixelMapRepository.save(pixel);
    return pixel;
  }

  async update(
    id: string,
    updatePixelMapDto: UpdatePixelMapDto,
  ): Promise<PixelMap> {
    const pixel = await this.findOne(id);
    Object.assign(pixel, updatePixelMapDto);

    if (updatePixelMapDto.geom) {
      pixel.geom = parse(updatePixelMapDto.geom) as Geometry;
    }

    return this.pixelMapRepository.save(pixel);
  }

  async remove(id: string): Promise<void> {
    const pixel = await this.findOne(id);
    await this.pixelMapRepository.remove(pixel);
  }
}
