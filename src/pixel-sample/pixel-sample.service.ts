import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { PixelSample } from './entities/pixel-sample.entity';
import { CreatePixelSampleDto } from './dto/create-pixel-sample.dto';
import { UpdatePixelSampleDto } from './dto/update-pixel-sample.dto';
import { parse } from 'wellknown';
import { Geometry } from 'geojson';
import { Sample } from 'src/sample/entities/sample.entity';

@Injectable()
export class PixelSampleService {
  constructor(
    @InjectRepository(PixelSample)
    private readonly pixelSampleRepository: Repository<PixelSample>,
  ) {}

  async findAll(): Promise<PixelSample[]> {
    return this.pixelSampleRepository.find({ relations: ['sample'] });
  }

  async findOne(id: string): Promise<PixelSample> {
    const pixel = await this.pixelSampleRepository.findOne({
      where: { id },
      relations: ['sample'],
    });
    if (!pixel) throw new NotFoundException(`Píxel con ID ${id} no encontrado`);
    return pixel;
  }

  async create(
    createPixelSampleDto: CreatePixelSampleDto,
  ): Promise<PixelSample> {
    const pixel = this.pixelSampleRepository.create({
      ...createPixelSampleDto,
      geom: parse(createPixelSampleDto.geom) as Geometry,
      sample: { id: createPixelSampleDto.sample } as Sample,
    });

    await this.pixelSampleRepository.save(pixel);
    return pixel;
  }

  async update(
    id: string,
    updatePixelSampleDto: UpdatePixelSampleDto,
  ): Promise<PixelSample> {
    const pixel = await this.findOne(id);
    Object.assign(pixel, updatePixelSampleDto);

    if (updatePixelSampleDto.geom) {
      pixel.geom = parse(updatePixelSampleDto.geom) as Geometry;
    }

    return this.pixelSampleRepository.save(pixel);
  }

  async remove(id: string): Promise<void> {
    const pixel = await this.findOne(id);
    await this.pixelSampleRepository.remove(pixel);
  }
}
