import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Geometry } from './entities/geometry.entity';
import { Area } from 'src/area/entities/area.entity';
import { UpdateGeometryDto } from './dto/update-geometry.dto';
import { CreateGeometryDto } from './dto/create-geometry.dto';

@Injectable()
export class GeometryService {
  constructor(
    @InjectRepository(Geometry)
    private readonly geometryRepository: Repository<Geometry>,

    @InjectRepository(Area)
    private readonly areaRepository: Repository<Area>,
  ) {}

  async findAll(
    page: number = 1,
    limit: number = 10,
    projectId?: string,
    bbox?: [number, number, number, number],
  ) {
    const query = this.geometryRepository
      .createQueryBuilder('geometry')
      .leftJoinAndSelect('geometry.area', 'area')
      .where('1=1');

    if (projectId) {
      query.andWhere('area.projectId = :projectId', { projectId });
    }

    if (bbox) {
      query.andWhere(
        'ST_Intersects(ST_MakeEnvelope(:minLng, :minLat, :maxLng, :maxLat, 4326), geometry.geom)',
        { minLng: bbox[0], minLat: bbox[1], maxLng: bbox[2], maxLat: bbox[3] },
      );
    }

    query.take(limit).skip((page - 1) * limit);

    const [geometries, total] = await query.getManyAndCount();

    return {
      success: true,
      data: geometries,
      pagination: {
        total,
        page,
        limit,
      },
    };
  }

  async findOne(id: string) {
    const geometry = await this.geometryRepository.findOne({
      where: { id },
      relations: ['area'],
    });

    if (!geometry) {
      throw new NotFoundException(`Geometría con ID ${id} no encontrada`);
    }

    return { success: true, data: geometry };
  }

  async create(
    createGeometryDto: CreateGeometryDto,
  ): Promise<{ success: boolean; data: Geometry }> {
    const area = await this.areaRepository.findOne({
      where: { id: createGeometryDto.areaId },
    });

    if (!area) {
      throw new NotFoundException(
        `Área con ID ${createGeometryDto.areaId} no encontrada`,
      );
    }

    let geometry = await this.geometryRepository.findOne({ where: { area } });

    if (geometry) {
      throw new Error(
        `Ya existe una geometría para el área con ID ${createGeometryDto.areaId}`,
      );
    }

    geometry = this.geometryRepository.create({
      ...createGeometryDto,
      area,
    });

    await this.geometryRepository.save(geometry);
    return { success: true, data: geometry };
  }

  async update(geometryId: string, geomData: UpdateGeometryDto | null) {
    const geometry = await this.geometryRepository.findOne({
      where: { id: geometryId },
    });

    if (!geometry) {
      throw new NotFoundException(
        `Geometría con ID ${geometryId} no encontrada`,
      );
    }

    if (geomData) {
      await this.geometryRepository.update(geometry.id, geomData);
    }

    return this.findOne(geometry.id);
  }

  async remove(id: string): Promise<{ success: boolean }> {
    const geometry = await this.geometryRepository.findOne({ where: { id } });

    if (!geometry) {
      throw new NotFoundException(`Geometría con ID ${id} no encontrada`);
    }

    await this.geometryRepository.delete(id);
    return { success: true };
  }
}
