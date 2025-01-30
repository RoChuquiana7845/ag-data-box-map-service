import { Test, TestingModule } from '@nestjs/testing';
import { PixelMapService } from './pixel-map.service';

describe('PixelMapService', () => {
  let service: PixelMapService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [PixelMapService],
    }).compile();

    service = module.get<PixelMapService>(PixelMapService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
