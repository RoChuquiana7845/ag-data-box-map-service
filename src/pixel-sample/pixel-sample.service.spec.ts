import { Test, TestingModule } from '@nestjs/testing';
import { PixelSampleService } from './pixel-sample.service';

describe('PixelSampleService', () => {
  let service: PixelSampleService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [PixelSampleService],
    }).compile();

    service = module.get<PixelSampleService>(PixelSampleService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
