import {
  Controller,
  Get,
  Param,
  Put,
  Query,
  Body,
  UseGuards,
  Post,
  Delete,
} from '@nestjs/common';
import { GeometryService } from './geometry.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiQuery,
  ApiResponse,
} from '@nestjs/swagger';
import { UpdateGeometryDto } from './dto/update-geometry.dto';
import { CreateGeometryDto } from './dto/create-geometry.dto';

@ApiTags('Geometries')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('geometries')
export class GeometryController {
  constructor(private readonly geometryService: GeometryService) {}

  @ApiOperation({
    summary: 'Obtener todas las geometrías con filtros opcionales',
  })
  @ApiQuery({
    name: 'projectId',
    required: false,
    description: 'Filtrar por ID de proyecto',
  })
  @ApiQuery({
    name: 'bbox',
    required: false,
    description: 'Filtrar por bounding box (minLng,minLat,maxLng,maxLat)',
  })
  @ApiQuery({
    name: 'simplified',
    required: false,
    description: 'Si es `true`, devuelve geometrías simplificadas',
  })
  @ApiResponse({
    status: 200,
    description: 'Lista de geometrías obtenidas correctamente',
  })
  @Get()
  findAll(
    @Query('page') page: number = 1,
    @Query('limit') limit: number = 10,
    @Query('projectId') projectId?: string,
    @Query('bbox') bbox?: string,
  ) {
    const bboxArray = bbox
      ? (bbox.split(',').map(Number) as [number, number, number, number])
      : undefined;
    return this.geometryService.findAll(
      Number(page),
      Number(limit),
      projectId,
      bboxArray,
    );
  }

  @ApiOperation({ summary: 'Obtener una geometría por ID' })
  @ApiResponse({ status: 200, description: 'Geometría obtenida correctamente' })
  @ApiResponse({ status: 404, description: 'Geometría no encontrada' })
  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.geometryService.findOne(id);
  }

  @ApiOperation({ summary: 'Crear una nueva geometría' })
  @ApiResponse({ status: 201, description: 'Geometría creada correctamente' })
  @ApiResponse({ status: 404, description: 'Área no encontrada' })
  @Post()
  create(@Body() createGeometryDto: CreateGeometryDto) {
    return this.geometryService.create(createGeometryDto);
  }

  @ApiOperation({ summary: 'Actualizar o eliminar una geometría por área' })
  @ApiResponse({
    status: 200,
    description: 'Geometría actualizada o eliminada correctamente',
  })
  @ApiResponse({ status: 404, description: 'Área no encontrada' })
  @Put(':geometryId')
  update(
    @Param('geometryId') geometryId: string,
    @Body() geomData: UpdateGeometryDto,
  ) {
    return this.geometryService.update(geometryId, geomData);
  }

  @ApiOperation({ summary: 'Eliminar una geometría por ID' })
  @ApiResponse({
    status: 200,
    description: 'Geometría eliminada correctamente',
  })
  @ApiResponse({ status: 404, description: 'Geometría no encontrada' })
  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.geometryService.remove(id);
  }
}
