import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Area } from './entities/area.entity';
import { CreateAreaDto } from './dto/create-area.dto';
import { UpdateAreaDto } from './dto/update-area.dto';
import { Project } from 'src/project/entities/project.entity';
import { AreaPaginationResponse } from './types/area.types';

@Injectable()
export class AreaService {
  constructor(
    @InjectRepository(Area)
    private readonly areaRepository: Repository<Area>,

    @InjectRepository(Project)
    private readonly projectRepository: Repository<Project>,
  ) {}

  async findAll(
    page: number = 1,
    limit: number = 10,
  ): Promise<AreaPaginationResponse> {
    const [areas, total] = await this.areaRepository.findAndCount({
      relations: ['project'],
      take: limit,
      skip: (page - 1) * limit,
    });
    return {
      success: true,
      data: areas,
      pagination: {
        total,
        page,
        limit,
      },
    };
  }

  async findOne(id: string): Promise<{ success: boolean; data: Area }> {
    const area = await this.areaRepository.findOne({
      where: { id },
      relations: ['project'],
    });
    if (!area) throw new NotFoundException(`Área con ID ${id} no encontrada`);
    return { success: true, data: area };
  }

  async create(
    createAreaDto: CreateAreaDto,
  ): Promise<{ success: boolean; data: Area }> {
    const project = await this.projectRepository.findOne({
      where: { id: createAreaDto.projectId },
    });

    if (!project) {
      throw new NotFoundException(
        `Proyecto con ID ${createAreaDto.projectId} no encontrado`,
      );
    }

    const area = this.areaRepository.create({
      ...createAreaDto,
      project: project.id,
    });

    await this.areaRepository.save(area);
    return this.findOne(area.id);
  }

  async update(
    id: string,
    updateAreaDto: UpdateAreaDto,
  ): Promise<{ success: boolean; data: Area }> {
    const area = await this.areaRepository.findOne({ where: { id } });
    if (!area) {
      throw new NotFoundException(`Área con ID ${id} no encontrada`);
    }

    if (updateAreaDto.projectId) {
      const project = await this.projectRepository.findOne({
        where: { id: updateAreaDto.projectId },
      });
      if (!project) {
        throw new NotFoundException(
          `Proyecto con ID ${updateAreaDto.projectId} no encontrado`,
        );
      }
    }

    await this.areaRepository.update(id, updateAreaDto);

    const updatedArea = await this.areaRepository.findOne({ where: { id } });
    if (!updatedArea) {
      throw new NotFoundException(`Error al recuperar el área actualizada`);
    }

    return {
      success: true,
      data: updatedArea,
    };
  }

  async remove(id: string): Promise<{ success: boolean }> {
    const { data: area } = await this.findOne(id);
    await this.areaRepository.remove(area);
    return { success: true };
  }
}
